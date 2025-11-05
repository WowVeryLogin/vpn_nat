use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::{Result, anyhow};
use encryption::Key;
use quinn::Connection;
use quinn::crypto::rustls::QuicClientConfig;
use rustls::crypto::CryptoProvider;
use rustls::crypto::ring;
use tokio::sync::mpsc::UnboundedReceiver;
use tokio::sync::mpsc::UnboundedSender;

use crate::tunnel::{FlowKey, Response};

mod insecure_verifier;

pub(crate) struct TcpUpstream {
    connection: Connection,
}

impl TcpUpstream {
    pub(crate) async fn new(vpn_addr: SocketAddr, aead_key: &Key) -> Self {
        CryptoProvider::install_default(ring::default_provider())
            .expect("failed to install default crypto provider");

        let crypto = rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(insecure_verifier::SkipServerVerification::new())
            .with_no_client_auth();
        let config =
            quinn::ClientConfig::new(Arc::new(QuicClientConfig::try_from(crypto).unwrap()));

        let mut cl = quinn::Endpoint::client((std::net::Ipv4Addr::UNSPECIFIED, 0).into()).unwrap();
        cl.set_default_client_config(config);
        let connection = cl.connect(vpn_addr, "vpn").unwrap().await.unwrap();

        auth_with_password(&connection, aead_key).await.unwrap();

        Self { connection }
    }
}

impl crate::tunnel::VPNUpstream for TcpUpstream {
    async fn new_connection(
        &mut self,
        key: FlowKey,
        mut rx: UnboundedReceiver<Vec<u8>>,
        tx: UnboundedSender<Response>,
    ) -> Result<Arc<tokio::sync::Notify>> {
        log::debug!("trying to connect to {:?}", key);
        let (mut sender, mut receiver) = self.connection.open_bi().await?;

        // |version, command (connect tcp stream), reserved, dst addr: |type (ipv4), addr|, dst port|
        let ip_octets = key.0.octets();
        let port = key.1;
        let mut req = Vec::with_capacity(10);
        req.push(0x05); // version
        req.push(0x01); // connect
        req.push(0x00); // reserved
        req.push(0x01); // IPv4
        req.extend_from_slice(&ip_octets);
        req.push((port >> 8) as u8);
        req.push((port & 0xff) as u8);
        sender.write_all(&req).await?;

        // |version, status, reserved, bound address: |type (ipv4), addr|, bound port|
        let mut buf = [0u8; 10];
        receiver.read_exact(&mut buf).await?;
        if buf[0] != 0x05 {
            return Err(anyhow!("invalid SOCKS5 version in connect reply"));
        }
        if buf[1] != 0x00 {
            return Err(anyhow!("SOCKS5 connect failed, status {}", buf[1]));
        }

        let notify = Arc::new(tokio::sync::Notify::new());

        let ntf = notify.clone();
        tokio::spawn(async move {
            let mut buf = [0u8; 4096];

            loop {
                tokio::select! {
                    _ = ntf.notified() => {
                        log::info!("closing stream");
                        return
                    },
                    Some(payload) = rx.recv() => {
                        log::debug!("writing data to socket: {}", payload.len());
                        sender.write_all(&payload).await.expect("writing payload");
                    },
                    n = receiver.read(&mut buf) => {
                        match n {
                            Ok(Some(n)) => {
                                log::debug!("sending data to kernel: {}", n);
                                tx.send(Response{
                                    payload: buf[..n].to_vec(),
                                    flow_key: key,
                                }).unwrap();
                            },
                            Ok(None) => {
                                log::debug!("received none bytes");
                                break;
                            },
                            Err(err) => {
                                log::warn!("reading from VPN socket: {}", err);
                                // deal with errors, retry/reconnect;
                                break;
                            },
                        };
                    }
                };
            }
        });
        Ok(notify)
    }
}

async fn auth_with_password(connection: &Connection, _aead_key: &Key) -> Result<()> {
    let username = b"testuser";
    let password = b"testpass";

    let (mut sender, mut reader) = connection.open_bi().await?;

    // |version, nmethods, method|
    sender.write_all(&[0x05, 1, 2]).await?;

    // |version, method|
    let mut buf = [0u8; 2];
    reader.read_exact(&mut buf).await?;

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
    sender.write_all(&auth_msg).await?;

    reader.read_exact(&mut buf).await?;
    if buf[0] != 0x01 {
        return Err(anyhow!("invalid auth version in reply"));
    }
    if buf[1] != 0x00 {
        return Err(anyhow!("username/password authentication failed"));
    }

    Ok(())
}
