use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr},
    sync::Arc,
};

use anyhow::Result;
use etherparse::{Ipv4HeaderSlice, PacketBuilder, TcpHeaderSlice, ip_number::TCP};
use rand::RngCore;
use rand::rngs::ThreadRng;
use std::net::SocketAddr;
use tokio::sync::{
    Notify,
    mpsc::{self, UnboundedReceiver, UnboundedSender},
};

pub(crate) type FlowKey = (Ipv4Addr, u16, u16);

type FlowTable = HashMap<FlowKey, TcpFlow>;

struct TcpFlow {
    our_seq: u32,
    our_ack: u32,
    local_addr: SocketAddr,
    remote_addr: SocketAddr,
    sender: UnboundedSender<Vec<u8>>,
    notify: Arc<Notify>,
}

pub(crate) struct Response {
    pub payload: Vec<u8>,
    pub flow_key: FlowKey,
}

pub(crate) trait L3Stream {
    async fn recv(&mut self, buf: &mut [u8]) -> Result<usize>;
    async fn send(&mut self, buf: &[u8]) -> Result<usize>;
}

pub(crate) trait VPNUpstream {
    fn new_connection(
        &mut self,
        key: FlowKey,
        rx: UnboundedReceiver<Vec<u8>>,
        tx: UnboundedSender<Response>,
    ) -> Result<Arc<tokio::sync::Notify>>;
}

pub(crate) struct Tunnel<IPv4STREAM, UPSTREAM> {
    tun: IPv4STREAM,
    upstream: UPSTREAM,
    flow_table: FlowTable,
    response_ipv4_stream: UnboundedReceiver<Response>,
    shared_channel: UnboundedSender<Response>,
    rng: ThreadRng,
}

impl<IPv4STREAM, UPSTREAM> Tunnel<IPv4STREAM, UPSTREAM> {
    pub(crate) fn new(tun: IPv4STREAM, upstream: UPSTREAM) -> Self {
        let (shared_channel, response_ipv4_stream) = mpsc::unbounded_channel::<Response>();
        Self {
            tun,
            upstream,
            flow_table: HashMap::new(),
            shared_channel,
            response_ipv4_stream,
            rng: rand::rng(),
        }
    }
}

impl<TUN: L3Stream, UPSTREAM: VPNUpstream> Tunnel<TUN, UPSTREAM> {
    fn process_packet(
        &mut self,
        ip_hdr: Ipv4HeaderSlice<'_>,
        packet: &[u8],
    ) -> Result<Option<Vec<u8>>> {
        if ip_hdr.protocol() != TCP {
            // support only TCP for now
            return Ok(None);
        }

        let tcp_start = ip_hdr.slice().len();

        if let Ok(tcp_hdr) = TcpHeaderSlice::from_slice(&packet[tcp_start..]) {
            let src_ip = Ipv4Addr::from(ip_hdr.source());
            let dst_ip = Ipv4Addr::from(ip_hdr.destination());
            let src_port = tcp_hdr.source_port();
            let dst_port = tcp_hdr.destination_port();
            let seq = tcp_hdr.sequence_number();
            let ack = tcp_hdr.acknowledgment_number();
            let payload = &packet[tcp_start + tcp_hdr.slice().len()..];
            log::debug!("received tcp header seq: {} ack: {}", seq, ack);

            let key = (dst_ip, dst_port, src_port);
            let flow = self.flow_table.get_mut(&key);
            if let Some(flow) = flow {
                if tcp_hdr.fin() {
                    log::debug!("killing connection");
                    flow.our_ack = seq.wrapping_add(1);
                    flow.our_seq = ack;
                    flow.sender.send(payload.to_vec())?;
                    flow.notify.notify_one();
                    let response = craft_ipv4_tcp(
                        flow.remote_addr,
                        flow.local_addr,
                        flow.our_seq,
                        flow.our_ack,
                        0x11, // ACK + FIN,
                        &[],
                    );
                    self.flow_table.remove(&key);
                    return Ok(Some(response));
                }

                if !payload.is_empty() {
                    flow.our_ack = seq.wrapping_add(payload.len() as u32);
                    flow.our_seq = ack;
                    flow.sender.send(payload.to_vec())?;
                    return Ok(Some(craft_ipv4_tcp(
                        flow.remote_addr,
                        flow.local_addr,
                        flow.our_seq,
                        flow.our_ack,
                        0x10, // ACK
                        &[],
                    )));
                }
            } else if tcp_hdr.syn() {
                let dst = SocketAddr::from((dst_ip, dst_port));
                let src = SocketAddr::from((src_ip, src_port));
                let our_isn: u32 = self.rng.next_u32();
                let kernel_next = seq.wrapping_add(1);

                let (tx, rx) = mpsc::unbounded_channel::<Vec<u8>>();
                let notify = self
                    .upstream
                    .new_connection(key, rx, self.shared_channel.clone())?;
                self.flow_table.insert(
                    key,
                    TcpFlow {
                        our_seq: our_isn,
                        our_ack: kernel_next,
                        local_addr: src,
                        remote_addr: dst,
                        sender: tx,
                        notify,
                    },
                );
                return Ok(Some(craft_ipv4_tcp(
                    dst,
                    src,
                    our_isn,
                    kernel_next,
                    0x12,
                    &[],
                )));
            }
        }

        Ok(None)
    }

    pub(crate) async fn loop_read(&mut self) {
        loop {
            let mut buf = [0u8; 65534];
            tokio::select! {
                packet = self.tun.recv(&mut buf) => {
                    let packet = match packet {
                        Ok(n) => &buf[..n],
                        Err(err) => {
                            log::error!("error reading ipv4 packet, {}", err);
                            return;
                        }
                    };
                    match Ipv4HeaderSlice::from_slice(packet) {
                        Ok(header) => {
                            if let Ok(Some(response)) = self.process_packet(header, packet) {
                                self.tun.send(&response).await.unwrap();
                            }
                        },
                        Err(err) => {
                            log::warn!("error parsing ipv4 packet, skipping it: {}", err);
                            continue;
                        },
                    };
                },
                Some(response) = self.response_ipv4_stream.recv() => {
                    if let Some(flow) = self.flow_table.get(&response.flow_key) {
                        self.tun.send(&craft_ipv4_tcp(
                            flow.remote_addr,
                            flow.local_addr,
                            flow.our_seq,
                            flow.our_ack,
                            0x18, // PSH + ACK
                            &response.payload,
                        )).await.unwrap();
                    }
                },
            };
        }
    }
}

pub(crate) fn craft_ipv4_tcp(
    src: SocketAddr,
    dst: SocketAddr,
    seq: u32,
    ack: u32,
    flags: u8,
    payload: &[u8],
) -> Vec<u8> {
    let src_ip = match src.ip() {
        IpAddr::V4(ip) => ip.octets(),
        IpAddr::V6(_) => panic!("not ipv4 address"),
    };

    let dst_ip = match dst.ip() {
        IpAddr::V4(ip) => ip.octets(),
        IpAddr::V6(_) => panic!("not ipv4 address"),
    };

    let mut builder =
        PacketBuilder::ipv4(src_ip, dst_ip, 64).tcp(src.port(), dst.port(), seq, 65535);
    if flags & 0x02 != 0 {
        builder = builder.syn();
    }
    if flags & 0x01 != 0 {
        builder = builder.fin();
    }
    if flags & 0x10 != 0 {
        builder = builder.ack(ack);
    }
    if flags & 0x08 != 0 {
        builder = builder.psh();
    }
    let mut buf = Vec::<u8>::with_capacity(builder.size(payload.len()));
    builder
        .write(&mut buf, payload)
        .expect("crafting kernel packet");

    log::debug!("responded with: seq {}, ack {}", seq, ack);
    buf
}
