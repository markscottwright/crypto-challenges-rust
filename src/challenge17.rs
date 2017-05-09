use base64::decode;
use aes::{encrypt_cbc, decrypt_cbc};
use bytes::{pad, unpad, valid_padding};
use rand;
use rand::distributions::{IndependentSample, Range};
use std::iter::once;

const BLOCK_SIZE: usize = 16;
static KEY: [u8; BLOCK_SIZE] = [1; BLOCK_SIZE];
static IV: [u8; BLOCK_SIZE] = [0; BLOCK_SIZE];

fn get_encrypted_string() -> (Vec<u8>, Vec<u8>) {

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
        .map(|x| encrypt_cbc(&pad(decode(x).unwrap(), BLOCK_SIZE), &KEY, &IV).unwrap())
        .collect();

    // return a random one
    let between = Range::new(0, plaintexts.len());
    let mut rng = rand::thread_rng();
    let i = between.ind_sample(&mut rng);

    ((&plaintexts[i]).clone(), IV.to_vec())
}

fn ciphertext_padding_valid(ciphertext: &[u8], iv: &[u8]) -> bool {
    match decrypt_cbc(ciphertext, &KEY, &iv) {
        Ok(cleartext) => valid_padding(&cleartext, BLOCK_SIZE),
        Err(_) => false,
    }
}

fn assemble_attack_block(pre_block: &[u8], cleartext: &[u8], guess: u8) -> Vec<u8> {
    // n is the padding we're working on
    let n = cleartext.len() + 1;

    // which byte are we decrypting?
    let guess_pos = BLOCK_SIZE - n;

    // set up attack_block to be:
    // [pre_block] + [pre_block ^ pad ^ guess] + [pre_block ^ pad ^ cleartext]
    let xored_guess = once(pre_block[guess_pos] ^ (n as u8) ^ guess);
    let xored_tail = pre_block[guess_pos + 1..]
        .iter()
        .zip(cleartext)
        .map(|(a, b)| a ^ b ^ (n as u8));
    pre_block[0..guess_pos]
        .iter()
        .cloned()
        .chain(xored_guess)
        .chain(xored_tail)
        .collect::<Vec<_>>()
}

pub fn decrypt_remaining_block_one(attack_ciphertext: &[u8], iv: &[u8], cleartext: &[u8]) -> Option<Vec<u8>> {

    for guess in 0..0xff {

        let attack_iv = assemble_attack_block(iv, cleartext, guess);

        if ciphertext_padding_valid(&attack_ciphertext, &attack_iv) {
            let mut updated_cleartext = cleartext.to_vec();
            updated_cleartext.insert(0, guess);

            // we've got our block
            if updated_cleartext.len() == BLOCK_SIZE {
                return Some(updated_cleartext);
            }
            // more to do
            else if let Some(c) = decrypt_remaining_block_one(&attack_ciphertext, &iv, &updated_cleartext) {
                return Some(c);
            }
        }
    }

    None
}

pub fn decrypt_block(block_num: usize,
                     ciphertext: &[u8],
                     iv: &[u8],
                     block_cleartext: &[u8])
                     -> Option<Vec<u8>> {

    // first block needs special handling, since we're varying the IV, not the
    // previous block
    assert!(block_num > 0);

    let prev_block_start = (block_num - 1) * BLOCK_SIZE;
    let prev_block = &ciphertext[prev_block_start..prev_block_start + BLOCK_SIZE];

    print!("\rblock_num = {} block_cleartext {:?} ", block_num, block_cleartext);
    let mut attack_ciphertext = ciphertext.iter().cloned()
        .take((block_num+1)*BLOCK_SIZE)
        .collect::<Vec<_>>();

    for guess in (0..0xff).rev() {

        // attack_ciphertext = [previous blocks] [attack_prev_block] [current block]
        let attack_prev_block = assemble_attack_block(prev_block, &block_cleartext, guess);

        for i in 0..BLOCK_SIZE {
            attack_ciphertext[i+prev_block_start] = attack_prev_block[i];
        }

        if ciphertext_padding_valid(&attack_ciphertext, &iv) {
            let mut cleartext = block_cleartext.to_vec();
            cleartext.insert(0, guess);

            if cleartext.len() == BLOCK_SIZE {
                return Some(cleartext);
            } else if let Some(c) = decrypt_block(block_num, ciphertext, iv, &cleartext) {
                return Some(c);
            }
        }
    }

    None
}

pub fn decrypt_block_one(ciphertext: &[u8], iv: &[u8]) -> Vec<u8> {
    let attack_ciphertext = &ciphertext[0..BLOCK_SIZE];
    for guess in 0..0xff {
        let attack_iv = assemble_attack_block(&iv, &Vec::new(), guess);
        if ciphertext_padding_valid(&attack_ciphertext, &attack_iv) {
            let cleartext = vec![guess];
            if let Some(c) = decrypt_remaining_block_one(&attack_ciphertext, &iv, &cleartext) {
                return c;
            }
        }
    }

    panic!("Decrypt failed")
}

pub fn decrypt_remaining_blocks(ciphertext: &[u8], iv: &[u8], block_1_cleartext: &[u8]) -> Vec<u8> {
    let mut cleartext = block_1_cleartext.to_vec();
    for block_num in 1..ciphertext.len() / BLOCK_SIZE {
        let clear_block = &mut decrypt_block(block_num, ciphertext, iv, &vec![]).unwrap();
        cleartext.append(clear_block);
    }

    cleartext
}

pub fn challenge17() {
    let (ciphertext, iv) = get_encrypted_string();
    //let (ciphertext, iv) = ([30, 159, 129, 7, 28, 253, 198, 188, 106, 136, 253,
    //144, 25, 70, 211, 147, 182, 248, 199, 161, 10, 8, 209, 175, 28, 212, 157,
    //125, 81, 58, 203, 202, 43, 224, 22, 101, 51, 233, 146, 10, 99, 13, 107, 150,
    //75, 2, 232, 164], IV);
    
    let block_one = decrypt_block_one(&ciphertext, &iv);
    let cleartext = decrypt_remaining_blocks(&ciphertext, &iv, &block_one);
    println!("{}", String::from_utf8_lossy(&unpad(cleartext)));
}

#[test]
fn test() {
    for _ in 0..1000 {
        let (ciphertext, iv) = get_encrypted_string();
        assert!(ciphertext_padding_valid(&ciphertext, &iv));
    }
}
