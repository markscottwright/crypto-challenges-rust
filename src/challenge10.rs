use base64::{decode_config, MIME};
use bytes::{unpad};
use aes::decrypt_cbc;

pub fn challenge10() {
    let ciphertext = decode_config(include_str!("challenge-10.dat"), MIME).unwrap();
    let cleartext = unpad(decrypt_cbc(&ciphertext, b"YELLOW SUBMARINE", &vec![0;16]).unwrap());
    println!("{}", String::from_utf8_lossy(&cleartext));
}
