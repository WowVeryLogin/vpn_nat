use anyhow::Result;

use crate::tunnel::L3Stream;
use std::io::{Read, Write};
use tokio::io::{self, Interest, Ready, unix::AsyncFd};
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
    async fn do_io(
        &mut self,
        read_buf: &mut [u8],
        write_buf: &mut Option<Vec<u8>>,
    ) -> Result<usize> {
        loop {
            let mut interest = Interest::READABLE;
            if write_buf.is_some() {
                interest |= Interest::WRITABLE;
            }

            let mut guard = self.fd.ready_mut(interest).await?;

            if let Some(wrt_buf) = write_buf
                && guard.ready().is_writable()
            {
                match guard.get_inner_mut().write(wrt_buf) {
                    Ok(n) => {
                        wrt_buf.drain(..n);
                        if wrt_buf.is_empty() {
                            *write_buf = None;
                        }
                    }
                    Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                        guard.clear_ready_matching(Ready::WRITABLE);
                    }
                    Err(e) => {
                        return Err(e.into());
                    }
                }
            }

            if guard.ready().is_readable() {
                match guard.get_inner_mut().read(read_buf) {
                    Ok(n) => {
                        return Ok(n);
                    }
                    Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                        guard.clear_ready_matching(Ready::READABLE);
                        continue;
                    }
                    Err(e) => {
                        return Err(e.into());
                    }
                }
            }
        }
    }
}
