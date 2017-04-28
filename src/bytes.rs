use std::cmp::Ordering;

pub fn xor1(bytes: &[u8], byte: u8) -> Vec<u8> {
    bytes.iter().map(|x| x ^ byte).collect()
}

// what percentage of characters are likely to be found in english text?
pub fn englishness(cleartext: &[u8]) -> f32 {
    let num_english_chars: u32 = cleartext
        .iter()
        .map(|c| match *c as char {
                 '0'...'9' => 1,
                 'a'...'z' => 1,
                 'A'...'Z' => 1,
                 '-' => 1,
                 ' ' => 1,
                 '\'' => 1,
                 '\"' => 1,
                 '.' => 1,
                 '!' => 1,
                 '?' => 1,
                 '\n' => 1,
                 _ => 0,
             })
        .sum();

    return num_english_chars as f32 / cleartext.len() as f32;
}

pub fn repeat_xor(bytes: &[u8], key: &[u8]) -> Vec<u8> {
    let mut dest = Vec::with_capacity(bytes.len());
    for (k, b) in key.iter().cycle().zip(bytes) {
        dest.push(k ^ b);
    }
    dest
}

pub fn hamming_weight(val: u32) -> u32 {
    let v1 = val - ((val >> 1) & 0x55555555);
    let v2 = (v1 & 0x33333333) + ((v1 >> 2) & 0x33333333);
    ((v2 + (v2 >> 4)) & 0xF0F0F0F).wrapping_mul(0x1010101) >> 24
}

pub fn hamming_distance(a: &[u8], b: &[u8]) -> u32 {
    a.iter()
        .zip(b)
        .map(|(a, b)| hamming_weight((a ^ b) as u32))
        .sum()
}

pub fn most_english_xor(ciphertext: &[u8]) -> Option<(u8, f32, Vec<u8>)> {
    (0..0xff)
        .map(|k| {
                 let cleartext = xor1(&ciphertext, k);
                 let rating = englishness(&cleartext);
                 (k, rating, cleartext)
             })
        .max_by(|x, y| x.1.partial_cmp(&y.1).unwrap_or(Ordering::Less))
}

// pkcs7 pad `bytes` to an even `bocksize`
pub fn pad(mut bytes: Vec<u8>, blocksize: usize) -> Vec<u8> {
    if bytes.len() % blocksize == 0 {
        bytes
    } else {
        let padding_bytes = blocksize - (bytes.len() % blocksize);
        let new_len = bytes.len() + padding_bytes;
        bytes.resize(new_len, padding_bytes as u8);
        bytes
    }
}

#[test]
fn test_repeat_xor() {
    use hexstring::fromhex;
    let expected = fromhex("0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f").unwrap();
    let clear = "Burning 'em, if you ain't quick and nimble
I go crazy when I hear a cymbal";
    let key = "ICE";

    assert_eq!(expected, repeat_xor(clear.as_bytes(), key.as_bytes()));
}

#[test]
fn test_hamming() {
    assert_eq!(0, hamming_weight(0));
    assert_eq!(3, hamming_weight(7));
    assert_eq!(16, hamming_weight(0xFFFF));
    assert_eq!(32, hamming_weight(0xFFFF_FFFF));
}

#[test]
fn test_hamming_distance() {
    assert_eq!(hamming_distance("this is a test".as_bytes(), "wokka wokka!!!".as_bytes()),
               37);
}

#[test]
fn test_padding() {
    assert_eq!([1, 2, 3, 4, 5, 3, 3, 3],
               pad(vec![1, 2, 3, 4, 5], 8).as_slice());
    assert_eq!([1, 2, 3, 4, 5, 6, 7, 8],
               pad(vec![1, 2, 3, 4, 5, 6, 7, 8], 8).as_slice());
}
