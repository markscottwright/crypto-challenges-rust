use bytes::*;
use hexstring::*;
use std::cmp::Ordering;

pub fn challenge3() {
    let ciphertext = fromhex("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")
        .unwrap();

    // Try out all one byte xor possibilities and select the one that creates the most english-like
    // string.  Need partial_cmd.unwrap_or(Less) because technically there's no good way to order
    // floats like NAN or -NAN and Rust is picky as f*.
    let answer = (0..0xff)
        .map(|k| {
                 let cleartext = xor1(&ciphertext, k);
                 let rating = englishness(&cleartext);
                 (k, rating, cleartext)
             })
        .max_by(|x, y| x.1.partial_cmp(&y.1).unwrap_or(Ordering::Less));
    let best_cleartext_bytes = answer.unwrap().2;
    let best_cleartext = String::from_utf8(best_cleartext_bytes).unwrap();

    println!("{}", best_cleartext);
}
