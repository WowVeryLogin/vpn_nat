use std::{cell::RefCell, pin::Pin, task::Poll};

use chacha20poly1305::Key;
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    net::{
        TcpStream as TokioTcpStream,
        tcp::{OwnedReadHalf as TokioReadHalf, OwnedWriteHalf as TokioWriteHalf},
    },
};

use crate::aead::Encrypter;
use crate::aead::frame_len;
use ringbuf::{StaticRb, traits::*};

pub struct TcpStream {
    rh: ReadHalf,
    wh: WriteHalf,
}

type EncType = StaticRb<u8, 16192>;
type DecType = StaticRb<u8, 8192>;

pub struct ReadHalf {
    inner: TokioReadHalf,
    encrypted_rb: EncType,
    decrypted_rb: DecType,
    enc: Encrypter,
}

pub struct WriteHalf {
    inner: RefCell<TokioWriteHalf>,
    inner_buffer: RefCell<Vec<u8>>,
    enc: Encrypter,
}

impl TcpStream {
    pub fn new(inner: TokioTcpStream, key: &Key) -> Self {
        let (rh, wh) = inner.into_split();
        Self {
            rh: ReadHalf {
                inner: rh,
                encrypted_rb: EncType::default(),
                decrypted_rb: DecType::default(),
                enc: Encrypter::new(key),
            },
            wh: WriteHalf {
                inner: RefCell::new(wh),
                inner_buffer: RefCell::new(vec![]),
                enc: Encrypter::new(key),
            },
        }
    }

    pub fn into_split(self) -> (ReadHalf, WriteHalf) {
        (self.rh, self.wh)
    }

    pub fn split(&mut self) -> (&mut ReadHalf, &mut WriteHalf) {
        (&mut self.rh, &mut self.wh)
    }
}

impl AsyncRead for ReadHalf {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        if self.decrypted_rb.occupied_len() > 0 {
            let len = self.decrypted_rb.pop_slice(buf.initialize_unfilled());
            buf.advance(len);
            return Poll::Ready(Ok(()));
        }

        let mut temp_buf = vec![0; self.encrypted_rb.vacant_len()];
        let mut temp_rb = ReadBuf::new(&mut temp_buf);

        let inner = Pin::new(&mut self.inner);
        match inner.poll_read(cx, &mut temp_rb) {
            Poll::Ready(Ok(())) => {
                if temp_rb.filled().is_empty() {
                    return Poll::Ready(Ok(()));
                }

                self.encrypted_rb.push_slice(temp_rb.filled());
                let mut len_slice = [0u8; 2];

                while self.encrypted_rb.peek_slice(&mut len_slice) == 2 {
                    let frame_len = frame_len(len_slice[0], len_slice[1]);
                    if self.encrypted_rb.occupied_len() >= frame_len {
                        let mut frame = vec![0; frame_len];
                        self.encrypted_rb.pop_slice(&mut frame);
                        let decoded_frame = self.enc.dec_aead_frame(&frame);
                        self.decrypted_rb.push_slice(&decoded_frame);
                    }
                }

                if self.decrypted_rb.occupied_len() > 0 {
                    let len = self.decrypted_rb.pop_slice(buf.initialize_unfilled());
                    buf.advance(len);
                    return Poll::Ready(Ok(()));
                }

                Poll::Pending
            }
            other => other,
        }
    }
}

impl AsyncWrite for WriteHalf {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<Result<usize, std::io::Error>> {
        if self.inner_buffer.borrow().is_empty() {
            *self.inner_buffer.borrow_mut() = self.enc.enc_aead_frame(buf);
        }

        let mut inner = self.inner.borrow_mut();
        let inner = Pin::new(&mut *inner);
        let result = inner.poll_write(cx, &self.inner_buffer.borrow());
        match result {
            Poll::Ready(Ok(n)) => {
                self.inner_buffer.borrow_mut().drain(..n);
                if !self.inner_buffer.borrow().is_empty() {
                    return Poll::Pending;
                }
                Poll::Ready(Ok(buf.len()))
            }
            other => other,
        }
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        let mut inner = self.inner.borrow_mut();
        let inner = Pin::new(&mut *inner);
        inner.poll_flush(cx)
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        let mut inner = self.inner.borrow_mut();
        let inner = Pin::new(&mut *inner);
        inner.poll_shutdown(cx)
    }
}

impl AsyncRead for TcpStream {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let inner = Pin::new(&mut self.rh);
        inner.poll_read(cx, buf)
    }
}

impl AsyncWrite for TcpStream {
    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        let inner = Pin::new(&mut self.wh);
        inner.poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        let inner = Pin::new(&mut self.wh);
        inner.poll_shutdown(cx)
    }

    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<Result<usize, std::io::Error>> {
        let inner = Pin::new(&mut self.wh);
        inner.poll_write(cx, buf)
    }
}

#[cfg(test)]
mod tests {
    use rand::{Rng, distr::Alphanumeric};
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        join,
        net::TcpListener,
    };

    use crate::aead::generate_key;

    use super::*;

    #[tokio::test]
    async fn test_read_write() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let key = generate_key();

        let s: String = rand::rng()
            .sample_iter(&Alphanumeric)
            .take(512)
            .map(char::from)
            .collect();
        let message = format!("Hello via TCP with encryption: {}", s);
        let expected = message.clone();

        let ltask = tokio::spawn(async move {
            let (connection, _) = listener.accept().await.unwrap();
            let mut connection = TcpStream::new(connection, &key);
            let mut buf = vec![0u8; message.len()];
            connection.read_exact(&mut buf).await.unwrap();
            assert_eq!(buf, message.as_bytes());
        });

        let mut conn = TcpStream::new(TokioTcpStream::connect(addr).await.unwrap(), &key);
        conn.write_all(expected.as_bytes()).await.unwrap();
        join!(async {
            ltask.await.unwrap();
        });
    }
}
