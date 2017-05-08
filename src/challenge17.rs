use base64::decode;
use aes::{encrypt_cbc, decrypt_cbc};
use bytes::{pad, valid_padding};
use rand;
use rand::distributions::{IndependentSample, Range};

static KEY: [u8; 16] = [1; 16];
static IV: [u8; 16] = [0; 16];

fn get_encrypted_string() -> Vec<u8> {

    // encrypt the strings
    let plaintext_strings = "MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=
        MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=
        MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==
        MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==
        MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl
        MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==
        MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==
        MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=
        MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=
        MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93";
    let plaintexts: Vec<_> = plaintext_strings
        .split_whitespace()
        .map(|x| encrypt_cbc(&pad(decode(x).unwrap(), 16), &KEY, &IV).unwrap())
        .collect();

    // return a random one
    let between = Range::new(0, plaintexts.len());
    let mut rng = rand::thread_rng();
    let i = between.ind_sample(&mut rng);

    (&plaintexts[i]).clone()
}

fn ciphertext_padding_valid(ciphertext: &[u8]) -> bool {
    match decrypt_cbc(ciphertext, &KEY, &IV) {
        Ok(cleartext) => valid_padding(&cleartext, 16),
        Err(_) => false,
    }
}

pub fn challenge17() {
    println!("{:?}", get_encrypted_string());
}

#[test]
fn test() {
    for _ in 0..1000 {
        assert!(ciphertext_padding_valid(&get_encrypted_string()));
    }
}
