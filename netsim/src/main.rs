use std::os::fd::AsRawFd;
use tokio_fd::AsyncFd as AsyncFdRw;

use tun::configure;

#[tokio::main]
async fn main() {
    let mut config = configure();
    config
        .tun_name("tun0")
        .address("10.0.0.2")
        .destination("10.0.0.1")
        .up();
    let dev = tun::create(&config).expect("creating tun device");

    dev.set_nonblock().unwrap();
    let (reader, writer) = dev.split();

    let socket = tokio::net::TcpListener::bind("127.0.0.1:6789")
        .await
        .unwrap();
    let (socket, _) = socket.accept().await.unwrap();
    let (mut rh, mut wh) = socket.into_split();

    tokio::spawn(async move {
        loop {
            tokio::io::copy(
                &mut AsyncFdRw::try_from(reader.as_raw_fd()).unwrap(),
                &mut wh,
            )
            .await
            .unwrap();
        }
    });

    tokio::spawn(async move {
        loop {
            tokio::io::copy(
                &mut rh,
                &mut AsyncFdRw::try_from(writer.as_raw_fd()).unwrap(),
            )
            .await
            .unwrap();
        }
    });
}
