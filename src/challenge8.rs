use base64::{decode_config, MIME};
use bytes::percent_unique_blocks;

pub fn challenge8() {
    for (i, line) in include_str!("challenge-8.dat").lines().enumerate() {
        let ciphertext = decode_config(line, MIME).unwrap();
        if percent_unique_blocks(16, &ciphertext) < 0.99 {
            println!("{} {} {:?}",
                     i,
                     percent_unique_blocks(16, &ciphertext),
                     line);
        }
    }
}
