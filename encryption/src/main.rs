use std::{fs::File, io::Write};

use encryption::aead::generate_key;

fn main() {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    let mut key_file = File::create("key.pem").unwrap();
    key_file
        .write_all(cert.signing_key.serialize_pem().as_bytes())
        .unwrap();
    let mut cert_file = File::create("cert.pem").unwrap();
    cert_file.write_all(cert.cert.pem().as_bytes()).unwrap();

    let aead_key = generate_key();
    let mut aead_file = File::create("xchacha20.key").unwrap();
    aead_file.write_all(&aead_key).unwrap();
}
