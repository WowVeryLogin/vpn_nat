use anyhow::Result;

use crate::tunnel::L3Stream;
use std::io::{Read, Write};
use tokio::io::unix::AsyncFd;
use tun::{Device, configure};

pub(crate) struct Tun {
    fd: AsyncFd<Device>,
}

impl Tun {
    pub(crate) fn new() -> Self {
        let mut config = configure();
        config
            .tun_name("tun0")
            .address("10.0.0.2")
            .destination("10.0.0.1")
            .up();
        let dev = tun::create(&config).expect("creating tun device");
        dev.set_nonblock()
            .expect("setting tun device for non_block mode");

        let fd = AsyncFd::new(dev).expect("moving tun to async fd");
        Self { fd }
    }
}

impl L3Stream for Tun {
    async fn recv(&mut self, buf: &mut [u8]) -> Result<usize> {
        loop {
            let mut guard = self.fd.readable_mut().await?;
            match guard.try_io(|inner| inner.get_mut().read(buf)) {
                Ok(result) => return result.map_err(|e| e.into()),
                Err(_would_block) => continue,
            }
        }
    }

    async fn send(&mut self, buf: &[u8]) -> Result<usize> {
        loop {
            let mut guard = self.fd.writable_mut().await?;
            match guard.try_io(|inner| inner.get_mut().write(buf)) {
                Ok(result) => return result.map_err(|e| e.into()),
                Err(_would_block) => continue,
            }
        }
    }
}
