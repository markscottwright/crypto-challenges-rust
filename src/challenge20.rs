use bytes::*;
use aes::encrypt_ctr;
use base64::decode;
use challenge6::transpose;

pub fn solve_repeated_xor(ciphertext: &[u8], keysize: usize) -> Vec<u8> {
    let mut key = Vec::new();
    for c in transpose(&ciphertext, keysize) {
        let (k, _, _) = most_english_xor(&c).unwrap();
        key.push(k);
    }
    key
}

fn concat_prefixes(vecs: &Vec<Vec<u8>>, prefix_len: usize) -> Vec<u8> {
    let mut concatted: Vec<u8> = Vec::new();
    for c in vecs {
        concatted.extend(c[0..prefix_len].iter());
    }
    concatted
}

// Note that this is essentially the same as challenge 6.
pub fn challenge20() {
    let key = b"YELLOW SUBMARINE";
    let nonce = 0;
    let cleartexts = include_str!("challenge-20.dat")
        .lines()
        .map(|x| decode(x).unwrap())
        .collect::<Vec<_>>();
    let ciphertexts = cleartexts
        .iter()
        .map(|cleartext| encrypt_ctr(cleartext, key, &nonce).unwrap())
        .collect::<Vec<_>>();

    let shortest_ciphertext_len = ciphertexts.iter().map(|c| c.len()).min().unwrap();
    let concatted_ciphertexts = concat_prefixes(&ciphertexts, shortest_ciphertext_len);
    let key = solve_repeated_xor(&concatted_ciphertexts, shortest_ciphertext_len);

    for c in &ciphertexts {
        println!("{}",
                 String::from_utf8_lossy(&repeat_xor(&c, &key)[0..shortest_ciphertext_len]));
    }
}
