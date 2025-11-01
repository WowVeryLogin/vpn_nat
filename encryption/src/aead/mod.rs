use aead::{Aead, AeadCore, KeyInit, OsRng};
use chacha20poly1305::{Key, XChaCha20Poly1305};

const NONCE_LEN: usize = 24;

pub struct Encrypter {
    cipher: XChaCha20Poly1305,
}

pub fn frame_len(hb: u8, lb: u8) -> usize {
    (((hb as u16) << 8) | (lb as u16)) as usize + 2
}

pub fn generate_key() -> Key {
    XChaCha20Poly1305::generate_key(&mut OsRng)
}

impl Encrypter {
    pub fn new(key: &Key) -> Self {
        Self {
            cipher: XChaCha20Poly1305::new(key),
        }
    }

    pub fn enc_aead_frame(&self, buf: &[u8]) -> Vec<u8> {
        let nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng);
        let payload = self.cipher.encrypt(&nonce, buf).expect("aead ecnryption");

        let len = nonce.len() + payload.len();
        let mut result: Vec<u8> = vec![((len >> 8) & 0xff) as u8, (len & 0xff) as u8];
        result.extend_from_slice(&nonce);
        result.extend_from_slice(&payload);
        result
    }

    pub fn dec_aead_frame(&self, buf: &[u8]) -> Vec<u8> {
        let nonce = &buf[2..2 + NONCE_LEN];
        let text = &buf[2 + NONCE_LEN..];
        self.cipher
            .decrypt(nonce.into(), text)
            .expect("aead decrypt")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_aead() {
        let key = generate_key();
        let enc = Encrypter::new(&key);
        let text = "Hello text!";
        let frame = enc.enc_aead_frame(text.as_bytes());
        let result = enc.dec_aead_frame(&frame);
        assert_eq!(text.as_bytes(), result);
    }
}
