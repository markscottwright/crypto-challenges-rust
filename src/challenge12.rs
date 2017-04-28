use aes::encrypt_ecb;
use crypto::symmetriccipher;
use bytes::pad;
use base64::decode;

fn oracle(data: &[u8]) -> Result<Vec<u8>, symmetriccipher::SymmetricCipherError> {
    let suffix = decode("Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg\
         aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq\
         dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg\
         YnkK")
            .unwrap();
    let key = [1u8; 16];

    let mut cleartext = data.iter()
        .cloned()
        .chain(suffix.iter().cloned())
        .collect::<Vec<u8>>();
    cleartext = pad(cleartext, key.len());

    encrypt_ecb(&cleartext, &key)
}

// given an encryption function, keep feeding it data until it expands it's
// ciphertext length, allowing us to determine the blocksize
pub fn find_blocksize(oracle_fn: fn(&[u8])
                                    -> Result<Vec<u8>, symmetriccipher::SymmetricCipherError>)
                      -> usize {

    let mut initial_size = oracle_fn(b"").unwrap().len();
    let mut i = 0;
    let mut first_overflow_pos = 0;
    loop {
        let current_size = oracle_fn(&vec![0;i]).unwrap().len();

        // cipher text has increased in size, so we must have pushed over a
        // block's worth of data
        if initial_size != current_size {

            // we've pushed two blocks, so we can determine block size
            if first_overflow_pos > 0 {
                break;
            }
            // only one block - remember where we were when we overflowed the
            // first block
            else {
                first_overflow_pos = i;
                initial_size = current_size;
            }
        }

        i = i + 1;
    }

    i - first_overflow_pos
}

pub fn is_ecb(oracle_fn: fn(&[u8]) -> Result<Vec<u8>, symmetriccipher::SymmetricCipherError>,
              blocksize: usize)
              -> bool {

    let ciphertext = oracle_fn(&vec![0u8; blocksize*2]).unwrap();
    ciphertext[0..blocksize] == ciphertext[blocksize..blocksize * 2]
}

pub fn challenge12() {
    let blocksize = find_blocksize(oracle);
    let using_ecb = is_ecb(oracle, blocksize);
    print!("blocksize = {} ", blocksize);
    println!("is ecb {}", using_ecb);

}
