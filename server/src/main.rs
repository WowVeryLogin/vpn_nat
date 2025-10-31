use anyhow::{Result, anyhow};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};

const USERNAME: &str = "testuser";
const PASSWORD: &str = "testpass";

struct TargetInfo {
    stream: TcpStream,
}

#[tokio::main]
async fn main() -> Result<()> {
    let listener = TcpListener::bind("172.28.0.3:1080").await?;
    println!("SOCKS5 VPN server with NAT listening on 172.28.0.3:1080");

    tokio::select! {
        _ = tokio::signal::ctrl_c() => {
            println!("Received SIGINT/SIGTERM, shutting down...");
        },
        _ = async {
            loop {
                let (mut client, client_addr) = listener.accept().await.expect("receiving connection");
                println!("new client: {}", client_addr);

                tokio::spawn(async move {
                    if let Err(e) = handle_client(&mut client).await {
                        eprintln!("client {} error: {:?}", client_addr, e);
                    }
                });
            }
        } => {},
    };
    Ok(())
}

async fn handle_client(client: &mut TcpStream) -> Result<()> {
    // ==== METHOD NEGOTIATION ====
    let mut header = [0u8; 2];
    client.read_exact(&mut header).await?;
    let nmethods = header[1] as usize;
    let mut methods = vec![0u8; nmethods];
    client.read_exact(&mut methods).await?;

    if !methods.contains(&0x02) {
        client.write_all(&[0x05, 0xFF]).await?;
        return Err(anyhow!("client does not support username/password"));
    }
    client.write_all(&[0x05, 0x02]).await?;

    // ==== USERNAME/PASSWORD AUTH ====
    let mut buf = [0u8; 1];
    client.read_exact(&mut buf).await?; // version
    if buf[0] != 0x01 {
        return Err(anyhow!("invalid auth version"));
    }

    client.read_exact(&mut buf[..1]).await?;
    let ulen = buf[0] as usize;
    let mut uname = vec![0u8; ulen];
    client.read_exact(&mut uname).await?;

    client.read_exact(&mut buf[..1]).await?;
    let plen = buf[0] as usize;
    let mut passwd = vec![0u8; plen];
    client.read_exact(&mut passwd).await?;

    if uname != USERNAME.as_bytes() || passwd != PASSWORD.as_bytes() {
        client.write_all(&[0x01, 0x01]).await?;
        return Err(anyhow!("invalid username/password"));
    }
    client.write_all(&[0x01, 0x00]).await?;

    // ==== CONNECT REQUEST ====
    let mut req = [0u8; 4];
    client.read_exact(&mut req).await?;
    if req[0] != 0x05 || req[1] != 0x01 {
        return Err(anyhow!("only CONNECT command supported"));
    }
    let addr_type = req[3];

    let target_addr: SocketAddr = match addr_type {
        0x01 => {
            let mut ip_buf = [0u8; 4];
            client.read_exact(&mut ip_buf).await?;
            let mut port_buf = [0u8; 2];
            client.read_exact(&mut port_buf).await?;
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

    client
        .write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
        .await?;

    let (mut client_r, mut client_w) = client.split();
    let (mut target_r, mut target_w) = target_info.stream.split();

    let c2t = tokio::io::copy(&mut client_r, &mut target_w);
    let t2c = tokio::io::copy(&mut target_r, &mut client_w);

    tokio::try_join!(c2t, t2c)?;

    Ok(())
}
