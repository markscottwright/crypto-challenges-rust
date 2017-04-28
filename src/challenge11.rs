use rand;
use rand::Rng;
use aes::{encrypt_cbc, encrypt_ecb};
use crypto::symmetriccipher;
use bytes::{pad, percent_unique_blocks};

fn random_aes_key() -> [u8;16] {
    let mut key = [0;16];
    rand::thread_rng().fill_bytes(&mut key);
    key
}

fn rand_u8() -> u8 {
    let mut rng1 = rand::thread_rng();
    rng1.gen::<u8>()
}

struct OracleResults {
    ciphertext: Vec<u8>,
    is_ecb: bool
}

fn oracle(data: &[u8]) -> Result<OracleResults, symmetriccipher::SymmetricCipherError> {
    let key = random_aes_key();
    let iv = random_aes_key();

    // create random prefix and suffix and wrap data with them
    let mut rng = rand::thread_rng();
    let prefix_len: usize = rng.gen::<usize>() % 5 + 6;
    let suffix_len: usize = rng.gen::<usize>() % 5 + 6;
    let mut cleartext = (0..prefix_len).map(|_| rand_u8())
        .chain(data.iter().cloned())
        .chain((0..suffix_len).map(|_| rand_u8()))
        .collect::<Vec<u8>>();
    cleartext = pad(cleartext, key.len());

    // use cbc/ecb randomly
    if rng.gen() {
        let results = try!(encrypt_cbc(&cleartext, &key, &iv));
        Ok(OracleResults{ciphertext:results, is_ecb:false})
    } else {
        let results = try!(encrypt_ecb(&cleartext, &key));
        Ok(OracleResults{ciphertext: results, is_ecb:true})
    }
}

pub fn challenge11() {
    let blocksize = 16;
    for _ in 0..100 {
        let cleartext = vec![0;blocksize*10];
        let oracle_results = oracle(&cleartext).unwrap();
        let all_blocks_unique = percent_unique_blocks(blocksize, &oracle_results.ciphertext) > 0.99;
        assert_eq!(all_blocks_unique, !oracle_results.is_ecb);
        if all_blocks_unique && oracle_results.is_ecb {
            println!("FAILED!!! Expected unique blocks iff CBC mode");
        }
    }
    println!("Passed...");
}

#[test]
fn test() {
    let ans = oracle(b"SOME TEST DATA12");
    assert!(ans.unwrap().ciphertext.len() >= b"SOME TEST DATA12".len() + 10);
}
