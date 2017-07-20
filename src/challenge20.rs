use aes::encrypt_ctr;
use base64::decode;

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
}
