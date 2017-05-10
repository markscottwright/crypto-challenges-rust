use aes::encrypt_ecb;
use crypto::symmetriccipher;
use bytes::pad;
use base64::decode;
use hexstring::fromhex;
use challenge12;

fn oracle(data: &[u8]) -> Result<Vec<u8>, symmetriccipher::SymmetricCipherError> {
    let suffix = decode("Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg\
         aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq\
         dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg\
         YnkK")
            .unwrap();
    let prefix = fromhex("707e8df2087691cf209d9660c6ae1f9982305b848c0e3597365facb808be27e0\
                          16f98500e6")
            .unwrap();
    let key = [1u8; 16];

    let mut cleartext = prefix
        .iter()
        .chain(data.iter())
        .chain(suffix.iter())
        .cloned()
        .collect::<Vec<u8>>();
    cleartext = pad(cleartext, key.len());

    encrypt_ecb(&cleartext, &key)
}

fn find_prefix_len(oracle_fn: fn(&[u8]) -> Result<Vec<u8>, symmetriccipher::SymmetricCipherError>,
                   blocksize: usize)
                   -> usize {

    // insert 4 blocks and look for the first repeated two blocks.  We know that
    // the prefix starts before there.  We need four, since three could
    // potentially end up with blocks one and three split.  Four guarantees two
    // consecutive blocks containing all the same cleartext.
    let ciphertext = oracle_fn(&vec![1u8; 4*blocksize]).unwrap();
    let num_blocks = ciphertext.len() / blocksize;
    let mut prefix_blocks_with_padding = 0;
    for i in 0..(num_blocks - 1) {
        if ciphertext[(i * blocksize)..((i + 1) * blocksize)] ==
           ciphertext[((i + 1) * blocksize)..((i + 2) * blocksize)] {
            prefix_blocks_with_padding = i;
            break;
        }
    }

    // We now have an upper bound for the prefix len.  Add two blocks known
    // value to the end, plus blocksize..0 bytes.
    let mut end_of_prefix_len = 0;
    for i in 0..(blocksize - 1) {
        let ciphertext = oracle_fn(&vec![1u8; 2*blocksize+i]).unwrap();
        let first_block_start = prefix_blocks_with_padding * blocksize;
        let second_block_start = (prefix_blocks_with_padding + 1) * blocksize;
        if ciphertext[first_block_start..second_block_start] ==
           ciphertext[second_block_start..(second_block_start + blocksize)] {
            end_of_prefix_len = i;
            break;
        }
    }

    (prefix_blocks_with_padding - 1) * blocksize + (blocksize - end_of_prefix_len)
}

pub fn challenge14() {
    let blocksize = challenge12::find_blocksize(oracle);
    let prefix_len = find_prefix_len(oracle, blocksize);

    // wrap oracle with a closure that prefixes enough bytes to create even
    // blocks out of the oracle's prefix, then chops off those front blocks from
    // the cipertext, leaving only the enciphered attacking bytes at the
    // beginning of the ciphertext.
    let oracle_without_prefix =
        |cleartext: &[u8]| -> Result<Vec<u8>, symmetriccipher::SymmetricCipherError> {
            let num_round_up_bytes = blocksize - (prefix_len % blocksize);
            let cleartext_with_choppable_prefix = (0..num_round_up_bytes)
                .map(|_| 0u8)
                .chain(cleartext.iter().cloned())
                .collect::<Vec<_>>();
            let mut ciphertext = oracle(&cleartext_with_choppable_prefix).unwrap();
            Ok(ciphertext.split_off(prefix_len + num_round_up_bytes))
        };

    let using_ecb = challenge12::is_ecb(&oracle_without_prefix, blocksize);
    let suffix_length = challenge12::length_of_suffix(&oracle_without_prefix, blocksize);
    let suffix = challenge12::crack_ecb_with_known_blocksize_and_suffix(&oracle_without_prefix,
                                                                        blocksize,
                                                                        suffix_length);

    println!("blocksize = {} ", blocksize);
    println!("prefix len = {} ", prefix_len);
    println!("is ecb {}", using_ecb);
    println!("suffix len {}", suffix_length);
    println!("suffix = {}", String::from_utf8_lossy(&suffix.unwrap()));
}
