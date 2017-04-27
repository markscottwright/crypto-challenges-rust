use base64::{decode_config, MIME};
use aes::decrypt_ecb;

pub fn challenge7() {
    let ciphertext = decode_config(include_str!("challenge-1-7.dat"), MIME).unwrap();
    let key = "YELLOW SUBMARINE".as_bytes();

    let cleartext = decrypt_ecb(&ciphertext, key).unwrap();
    println!("{}", String::from_utf8_lossy(&cleartext));
}
