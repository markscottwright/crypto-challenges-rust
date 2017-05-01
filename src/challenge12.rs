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

pub fn length_of_suffix(oracle_fn: fn(&[u8])
                                      -> Result<Vec<u8>, symmetriccipher::SymmetricCipherError>,
                        blocksize: usize)
                        -> usize {

    let mut last_cipher_len: Option<usize> = None;

    // keep adding to cleartext size until we overflow a block
    for i in 0..blocksize {
        let cur_cipher_len = oracle_fn(&vec![1u8;i]).unwrap().len();
        let overflowed = match last_cipher_len {
            None => {
                last_cipher_len = Some(cur_cipher_len);
                false
            }
            Some(x) if x == cur_cipher_len => false,
            _ => true,
        };

        // need to add i to make it overflow, so the suffix's length (mod
        // blocksize) is blocksize - (i - 1)
        if overflowed {
            let suffix_mod_blocksize = blocksize - (i - 1);

            // last_cipher_len was suffix + padding, so round down to nearest
            // blocksize and then add the extra suffix length
            let suffix_len = last_cipher_len.unwrap() - blocksize + suffix_mod_blocksize;
            return suffix_len;
        }
    }

    panic!("Unexpected error - never found suffix length!")
}

pub fn crack_ecb_with_known_blocksize_and_suffix
    (oracle_fn: fn(&[u8]) -> Result<Vec<u8>, symmetriccipher::SymmetricCipherError>,
     blocksize: usize,
     suffix_len: usize)
     -> Result<Vec<u8>, symmetriccipher::SymmetricCipherError> {

    let mut decrypted_suffix = Vec::with_capacity(suffix_len);

    for _ in 0..blocksize {

        // match block, 0's 
        // test block,  0's || suffix_so_far || 0..ff
        let short_block_len = blocksize - decrypted_suffix.len() - 1;
        let mut match_block = Vec::with_capacity(blocksize);
        let mut test_block =  Vec::with_capacity(blocksize);
        for _ in 0..short_block_len {
            match_block.push(0);
            test_block.push(0);
        }
        for b in decrypted_suffix.iter().cloned() {
            test_block.push(b);
        }
        test_block.push(0);

        // Keep varying the last byte until the enciphered block matches the
        // enciphered block from the one-byte-short match block.  Then we know what
        // the first byte is in the suffix.
        let match_ciphertext_block = &oracle_fn(&match_block).unwrap()[0..blocksize];
        for b in 0..0xff {
            test_block[blocksize-1] = b;
            let test_ciphertext_block = &oracle_fn(&test_block).unwrap()[0..blocksize];
            if test_ciphertext_block == match_ciphertext_block {
                decrypted_suffix.push(b);
                break;
            }
        }
    }

    Ok(decrypted_suffix)
}

pub fn challenge12() {
    let blocksize = find_blocksize(oracle);
    let using_ecb = is_ecb(oracle, blocksize);
    let suffix_length = length_of_suffix(oracle, blocksize);
    let suffix = crack_ecb_with_known_blocksize_and_suffix(oracle, blocksize, suffix_length);
    print!("blocksize = {} ", blocksize);
    println!("is ecb {}", using_ecb);
    println!("suffix len {}", suffix_length);
    println!("suffix {}", String::from_utf8_lossy(&suffix.unwrap()));
}
