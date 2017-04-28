use bytes::*;
use std::cmp::Ordering;
use base64::{decode_config, MIME};

pub fn transpose(data: &[u8], keysize: usize) -> Vec<Vec<u8>> {
    // create our vec of vecs
    let mut transposed = Vec::new();
    for _ in 0..keysize {
        transposed.push(Vec::new());
    }

    // go through each chunk and add the byte to the appropriate vec in
    // transposed
    for c in data.chunks(keysize) {
        for (i, b) in c.iter().enumerate() {
            transposed[i].push(*b);
        }
    }
    transposed
}

pub fn challenge6() {
    let ciphertext = decode_config(include_str!("challenge-6.dat"), MIME).unwrap();

    // find key size
    let mut answers = (2..40)
        .map(|keysize| {
            let d = hamming_distance(&ciphertext[0..keysize], &ciphertext[keysize..keysize * 2]) +
                    hamming_distance(&ciphertext[0..keysize],
                                     &ciphertext[keysize * 2..keysize * 3]) +
                    hamming_distance(&ciphertext[0..keysize],
                                     &ciphertext[keysize * 3..keysize * 4]);

            (keysize, (d * 100) / keysize as u32)
        })
        .collect::<Vec<_>>();
    answers.sort_by_key(|a| a.1);
    let likely_key_sizes = answers.iter().map(|a| a.0).take(4);

    // for likely key sizes, transpose matrix (so that each block was xored with
    // the same byte)
    let mut keys_and_ratings = Vec::new();
    for k in likely_key_sizes {
        let mut key = Vec::new();
        let mut rating = 0f32;
        for ciphertext in transpose(&ciphertext, k) {
            let (k, block_rating, _) = most_english_xor(&ciphertext).unwrap();
            key.push(k);
            rating = rating + block_rating;
        }
        keys_and_ratings.push((key, rating / k as f32));
    }
    keys_and_ratings.sort_by(|x, y| y.1.partial_cmp(&x.1).unwrap_or(Ordering::Less));

    let ref key = keys_and_ratings[0].0;
    let keystr = String::from_utf8_lossy(&key);
    let rating = keys_and_ratings[0].1;
    println!("{} {} {}", keystr, rating, key.len());

    println!("{}",
             String::from_utf8(repeat_xor(&ciphertext, key)).unwrap());
}
