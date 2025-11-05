use anyhow::Result;
use std::{fs::File, io::Read, path::Path};
use tokio::{self};

mod tcp;
mod tun;
mod tunnel;

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();

    let path = Path::new("/etc/xchacha20.key");
    let mut file = File::open(path)?;
    let mut aead_key = vec![];
    file.read_to_end(&mut aead_key)?;
    let aead_key = aead_key.as_slice().into();

    let tun = tun::Tun::new();
    let vpn = tcp::TcpUpstream::new("172.28.0.3:1080".parse().unwrap(), aead_key).await;
    let mut tunnel = tunnel::Tunnel::new(tun, vpn);

    tokio::select! {
        _ = tokio::signal::ctrl_c() => {
            println!("Received SIGINT/SIGTERM, shutting down...");
        },
        _ = tunnel.loop_read() => {},
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    // use super::*;

    // #[tokio::test]
    // async fn test_ipv4_tcp_parsing() {
    //     tokio::spawn(async move {
    //     //    let mut stream = TcpStream::connect("10.0.0.1:80").await.unwrap();
    //     //     stream.write_all(&[1,2,3,4,5,6,7,8]).await.unwrap();
    //     //     stream
    //     // });

    //     // let mut stream = TcpStream::connect("127.0.0.1:80").await.unwrap();

    // }
}
