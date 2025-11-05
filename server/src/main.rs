use anyhow::{Result, anyhow};
use quinn::{Connection, ServerConfig, TransportConfig};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use std::io::Read;
use std::sync::Arc;
use std::time::Duration;
use std::{
    fs::File,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::Path,
};
use tokio::net::TcpStream;

const USERNAME: &str = "testuser";
const PASSWORD: &str = "testpass";

struct TargetInfo {
    stream: TcpStream,
}

fn read_certs_from_file() -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)> {
    let certs = CertificateDer::from_pem_file("/etc/cert.pem").unwrap();
    let key = PrivateKeyDer::from_pem_file("/etc/key.pem").unwrap();
    Ok((vec![certs], key))
}

#[tokio::main]
async fn main() -> Result<()> {
    println!("SOCKS5 VPN server with NAT listening on 172.28.0.3:1080");
    let (certs, key) = read_certs_from_file().unwrap();

    let mut server_config = ServerConfig::with_single_cert(certs, key).unwrap();
    let mut transport_config = TransportConfig::default();

    transport_config.max_idle_timeout(None);
    transport_config.keep_alive_interval(Some(Duration::from_secs(10)));

    server_config.transport_config(Arc::new(transport_config));
    let server =
        quinn::Endpoint::server(server_config, "172.28.0.3:1080".parse().unwrap()).unwrap();

    let path = Path::new("/etc/xchacha20.key");
    let mut file = File::open(path)?;
    let mut aead_key = vec![];
    file.read_to_end(&mut aead_key)?;
    // let aead_key = aead_key.as_slice().into();

    tokio::select! {
        _ = tokio::signal::ctrl_c() => {
            println!("Received SIGINT/SIGTERM, shutting down...");
        },
        _ = async {
            while let Some(conn) = server.accept().await {
                tokio::spawn(async move {
                    let connection = conn.await.unwrap();
                    println!("new client: {}", connection.remote_address());
                    if let Err(e) = handle_client(connection).await {
                        eprintln!("client error: {:?}", e);
                    }
                });
            }
        } => {},
    };
    Ok(())
}

async fn handle_client(client: Connection) -> Result<()> {
    let (mut send, mut recv) = client.accept_bi().await?;

    // ==== METHOD NEGOTIATION ====
    let mut header = [0u8; 2];
    recv.read_exact(&mut header).await?;
    let nmethods = header[1] as usize;
    let mut methods = vec![0u8; nmethods];
    recv.read_exact(&mut methods).await?;

    if !methods.contains(&0x02) {
        send.write_all(&[0x05, 0xFF]).await?;
        return Err(anyhow!("client does not support username/password"));
    }
    send.write_all(&[0x05, 0x02]).await?;

    // ==== USERNAME/PASSWORD AUTH ====
    let mut buf = [0u8; 1];
    recv.read_exact(&mut buf).await?; // version
    if buf[0] != 0x01 {
        return Err(anyhow!("invalid auth version"));
    }

    recv.read_exact(&mut buf[..1]).await?;
    let ulen = buf[0] as usize;
    let mut uname = vec![0u8; ulen];
    recv.read_exact(&mut uname).await?;

    recv.read_exact(&mut buf[..1]).await?;
    let plen = buf[0] as usize;
    let mut passwd = vec![0u8; plen];
    recv.read_exact(&mut passwd).await?;

    if uname != USERNAME.as_bytes() || passwd != PASSWORD.as_bytes() {
        send.write_all(&[0x01, 0x01]).await?;
        return Err(anyhow!("invalid username/password"));
    }
    send.write_all(&[0x01, 0x00]).await?;

    // ==== CONNECT REQUEST ====
    loop {
        let (mut send, mut recv) = client.accept_bi().await?;
        println!("new stream inside client {:?}", client.remote_address());
        tokio::spawn(async move {
            let mut req = [0u8; 4];
            recv.read_exact(&mut req).await?;
            if req[0] != 0x05 || req[1] != 0x01 {
                return Err(anyhow!("only CONNECT command supported"));
            }
            let addr_type = req[3];

            let target_addr: SocketAddr = match addr_type {
                0x01 => {
                    let mut ip_buf = [0u8; 4];
                    recv.read_exact(&mut ip_buf).await?;
                    let mut port_buf = [0u8; 2];
                    recv.read_exact(&mut port_buf).await?;
                    let ip = Ipv4Addr::from(ip_buf);
                    let port = u16::from_be_bytes(port_buf);
                    SocketAddr::new(IpAddr::V4(ip), port)
                }
                _ => return Err(anyhow!("address type not supported")),
            };

            let target_stream = TcpStream::connect(target_addr).await?;

            let mut target_info = TargetInfo {
                stream: target_stream,
            };

            send.write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                .await?;

            let (mut target_r, mut target_w) = target_info.stream.split();

            let c2t = tokio::io::copy(&mut recv, &mut target_w);
            let t2c = tokio::io::copy(&mut target_r, &mut send);

            tokio::try_join!(c2t, t2c)?;

            Ok(())
        });
    }
}
