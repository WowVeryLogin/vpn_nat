use anyhow::{Result, anyhow};
use etherparse::{Ipv4HeaderSlice, PacketBuilder, TcpHeaderSlice, ip_number::TCP};
use log::debug;
use rand::RngCore;
use std::{
    collections::HashMap,
    net::{Ipv4Addr, SocketAddr},
    sync::Arc,
};
use tokio::io::AsyncWriteExt;
use tokio::sync::mpsc::UnboundedReceiver;
use tokio::sync::mpsc::{self, UnboundedSender};
use tokio::{self, io::AsyncReadExt, net::TcpStream};
use tun::configure;

struct Packet {
    seq: u32,
    ack: u32,
    payload: Vec<u8>,
    shutdown: bool,
}

type FlowKey = (Ipv4Addr, u16, u16);

struct FlowSender {
    sender: UnboundedSender<Packet>,
}

type FlowTable<'a> = HashMap<FlowKey, FlowSender>;

async fn auth_with_password(dst: SocketAddr) -> Result<TcpStream> {
    let vpn_socks5_addr: SocketAddr = "172.28.0.3:1080".parse()?;
    let username = b"testuser";
    let password = b"testpass";

    let mut connection = TcpStream::connect(vpn_socks5_addr).await?;

    // |version, nmethods, method|
    connection.write_all(&[0x05, 1, 2]).await?;

    // |version, method|
    let mut buf = [0u8; 2];
    connection.read_exact(&mut buf).await?;

    if buf[0] != 0x05 {
        return Err(anyhow!("invalid SOCKS5 version in method reply"));
    }
    if buf[1] != 2 {
        return Err(anyhow!("server does not support username/password auth"));
    }

    // |version, id_len, id, password_len, password|
    let mut auth_msg = Vec::with_capacity(3 + username.len() + password.len());
    auth_msg.push(0x01); // auth version
    auth_msg.push(username.len() as u8);
    auth_msg.extend_from_slice(username);
    auth_msg.push(password.len() as u8);
    auth_msg.extend_from_slice(password);
    connection.write_all(&auth_msg).await?;

    connection.read_exact(&mut buf).await?;
    if buf[0] != 0x01 {
        return Err(anyhow!("invalid auth version in reply"));
    }
    if buf[1] != 0x00 {
        return Err(anyhow!("username/password authentication failed"));
    }
    // |version, command (connect tcp stream), reserved, dst addr: |type (ipv4), addr|, dst port|
    let ip_octets = match dst.ip() {
        std::net::IpAddr::V4(ipv4) => ipv4.octets(),
        std::net::IpAddr::V6(_) => return Err(anyhow!("IPv6 not supported in this example")),
    };
    let port = dst.port();
    let mut req = Vec::with_capacity(10);
    req.push(0x05); // version
    req.push(0x01); // connect
    req.push(0x00); // reserved
    req.push(0x01); // IPv4
    req.extend_from_slice(&ip_octets);
    req.push((port >> 8) as u8);
    req.push((port & 0xff) as u8);
    connection.write_all(&req).await?;

    // |version, status, reserved, bound address: |type (ipv4), addr|, bound port|
    let mut buf = [0u8; 10];
    connection.read_exact(&mut buf).await?;
    if buf[0] != 0x05 {
        return Err(anyhow!("invalid SOCKS5 version in connect reply"));
    }
    if buf[1] != 0x00 {
        return Err(anyhow!("SOCKS5 connect failed, status {}", buf[1]));
    }

    Ok(connection)
}

struct IpAddr {
    ip: Ipv4Addr,
    port: u16,
}

fn craft_ipv4_tcp(
    src: IpAddr,
    dst: IpAddr,
    seq: u32,
    ack: u32,
    flags: u8,
    payload: &[u8],
) -> Vec<u8> {
    let mut builder = PacketBuilder::ipv4(src.ip.octets(), dst.ip.octets(), 64)
        .tcp(src.port, dst.port, seq, 65535);
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

    debug!("responded with: seq {}, ack {}", seq, ack);
    buf
}

struct Flow {
    our_seq: u32,
    our_ack: u32,
    local_ip: Ipv4Addr,
    local_port: u16,
    remote_ip: Ipv4Addr,
    remote_port: u16,
}

impl Flow {
    async fn run_connection(
        mut self,
        mut stream: TcpStream,
        mut outcoming: UnboundedReceiver<Packet>,
        tun_tx: UnboundedSender<Vec<u8>>,
    ) {
        let mut buf = [0u8; 1500];

        loop {
            tokio::select! {
                Some(packet) = outcoming.recv() => {
                    debug!("writing data to socket: {}", packet.payload.len());
                    stream.write_all(&packet.payload).await.expect("writing payload");
                    self.our_ack = packet.seq.wrapping_add(if packet.shutdown { packet.payload.len() as u32 } else { 1 });
                    self.our_seq = packet.ack;
                    let flags = if packet.shutdown {
                        0x11 // ACK + FIN
                    } else {
                        0x10 // ACK
                    };
                    tun_tx.send(craft_ipv4_tcp(
                        IpAddr {
                            ip: self.remote_ip,
                            port: self.remote_port,
                        },
                        IpAddr {
                            ip: self.local_ip,
                            port: self.local_port,
                        },
                        self.our_seq,
                        self.our_ack,
                        flags,
                        &[],
                    )).expect("sending ack packate");
                    if packet.shutdown {
                        return
                    }
                },
                n = stream.read(&mut buf) => {
                    match n {
                        Ok(0) => break,
                        Ok(n) => {
                            debug!("sending data to kernel: {}", n);
                            let _ = tun_tx.send(craft_ipv4_tcp(
                                IpAddr {
                                    ip: self.remote_ip,
                                    port: self.remote_port,
                                },
                                IpAddr {
                                    ip: self.local_ip,
                                    port: self.local_port,
                                },
                                self.our_seq,
                                self.our_ack,
                                0x18, // PSH + ACK
                                &buf[..n],
                            ));
                            Some(())
                        }
                        Err(_) => break,
                    };
                }
            };
        }
    }
}

async fn parse_ip(
    mut from_tun_rx: UnboundedReceiver<Vec<u8>>,
    to_tun_tx: UnboundedSender<Vec<u8>>,
) -> Result<()> {
    let mut flow_table: FlowTable = HashMap::new();
    let mut rng = rand::rng();

    loop {
        debug!("waiting for a new IP package");

        let Some(packet) = from_tun_rx.recv().await else {
            continue;
        };
        if packet.is_empty() {
            continue;
        }

        let packet = &packet;

        if let Ok(ip_hdr) = Ipv4HeaderSlice::from_slice(packet) {
            if ip_hdr.protocol() != TCP {
                continue;
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
                debug!("received tcp header seq: {} ack: {}", seq, ack);

                let key = (dst_ip, dst_port, src_port);
                let flow = flow_table.get(&key);
                if let Some(flow) = flow {
                    if tcp_hdr.fin() {
                        debug!("killing connection");
                        flow.sender.send(Packet {
                            seq,
                            ack,
                            payload: payload.to_vec(),
                            shutdown: true,
                        })?;
                        flow_table.remove(&key);
                        continue;
                    }

                    if !payload.is_empty() {
                        flow.sender.send(Packet {
                            seq,
                            ack,
                            payload: payload.to_vec(),
                            shutdown: false,
                        })?;
                    }
                } else if tcp_hdr.syn() {
                    let dst = SocketAddr::from((dst_ip, dst_port));

                    debug!("trying to connect to socks5 {:?}", dst);
                    let stream = auth_with_password(dst).await?;
                    let (tx, rx) = mpsc::unbounded_channel::<Packet>();

                    let our_isn: u32 = rng.next_u32();
                    let kernel_next = seq.wrapping_add(1);

                    // let flow = Arc::new(TcpFlow {
                    //     metadata: Mutex::new(FlowMetadata {
                    //         our_seq: our_isn,
                    //         our_ack: kernel_next,
                    //         local_ip: src_ip,
                    //         local_port: src_port,
                    //         remote_ip: dst_ip,
                    //         remote_port: dst_port,
                    //     }),
                    //     read_part: TokioMutex::new(read),
                    //     write_part: Mutex::new(write),
                    // });

                    flow_table.insert(key, FlowSender { sender: tx });

                    let flow = Flow {
                        our_seq: our_isn,
                        our_ack: kernel_next,
                        local_ip: src_ip,
                        local_port: src_port,
                        remote_ip: dst_ip,
                        remote_port: dst_port,
                    };

                    // let mt = flow.metadata.lock().unwrap();
                    to_tun_tx.send(craft_ipv4_tcp(
                        IpAddr {
                            ip: flow.remote_ip,
                            port: flow.remote_port,
                        },
                        IpAddr {
                            ip: flow.local_ip,
                            port: flow.local_port,
                        },
                        our_isn,
                        kernel_next,
                        0x12,
                        &[],
                    ))?;

                    let to_tun_tx = to_tun_tx.clone();
                    tokio::spawn(async move {
                        flow.run_connection(stream, rx, to_tun_tx).await;
                    });
                }
            }
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();

    let mut config = configure();
    config
        .tun_name("tun0")
        .address("10.0.0.2")
        .destination("10.0.0.1")
        .up();
    let dev = Arc::new(tun::create(&config).expect("creating tun device"));

    let (to_tun_tx, mut to_tun_rx) = mpsc::unbounded_channel::<Vec<u8>>();
    let (from_tun_tx, from_tun_rx) = mpsc::unbounded_channel();

    let dev_to_kernel = dev.clone();
    let responder = tokio::task::spawn_blocking(move || {
        while let Some(packet) = to_tun_rx.blocking_recv() {
            dev_to_kernel
                .send(packet.as_slice())
                .expect("sending back to kernel");
        }
    });

    let receiver = tokio::task::spawn_blocking(move || {
        loop {
            let mut buf = [0u8; 65535];
            let n = dev.recv(&mut buf).expect("reading from tun");
            from_tun_tx.send(buf[..n].to_vec()).unwrap();
        }
    });

    tokio::select! {
        _ = tokio::signal::ctrl_c() => {
            println!("Received SIGINT/SIGTERM, shutting down...");
        }
        _ = async {
            let _ = tokio::join!(
                receiver,
                responder,
                parse_ip(from_tun_rx, to_tun_tx)
            );
        } => {}
    }
    Ok(())
}
