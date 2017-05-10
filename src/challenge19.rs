use base64::decode;

pub fn challenge19() {
    let ciphertexts = include_str!("challenge-19.dat")
            .lines()
            .map(|x| decode(x).unwrap())
            .collect::<Vec<_>>();

    println!("{:?}", ciphertexts);
}
