use bytes::*;
use aes::encrypt_ctr;
use base64::decode;
use challenge6::transpose;

pub fn shortest_vec(vecs: &Vec<Vec<u8>>) -> usize {
    let mut min_len = vecs[0].len();
    let mut shortest_index = 0;

    for i in 1..vecs.len() {
        if vecs[i].len() < min_len {
            min_len = vecs[i].len();
            shortest_index = i;
        }
    }

    shortest_index
}

pub fn solve_repeated_xor(ciphertext: &[u8], keysize: usize) -> Vec<u8> {
    // copy and paste from challenge6.  Bad programmer...

    let mut key = Vec::new();
    for c in transpose(&ciphertext, keysize) {
        let (k, _, _) = most_english_xor(&c).unwrap();
        key.push(k);
    }

    {
        let keystr = String::from_utf8_lossy(&key);
        println!("{}", keystr);
    }

    key
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

    let shortest_ciphertext_index = shortest_vec(&ciphertexts);
    let shortest_ciphertext_len = ciphertexts[shortest_ciphertext_index].len();
    let mut concatted_ciphertexts: Vec<u8> = Vec::new();
    {
        for c in &ciphertexts {
            concatted_ciphertexts.extend(c[0..shortest_ciphertext_len].iter());
        }
    }

    let key = solve_repeated_xor(&concatted_ciphertexts, shortest_ciphertext_len);
    for c in &ciphertexts {
        println!("{}", String::from_utf8_lossy(&repeat_xor(&c, &key)[0..shortest_ciphertext_len]));
    }
}
