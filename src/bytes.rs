use rand;
use rand::Rng;
use std::cmp::Ordering;

pub fn xor1(bytes: &[u8], byte: u8) -> Vec<u8> {
    bytes.iter().map(|x| x ^ byte).collect()
}

pub fn rand_u8() -> u8 {
    let mut rng1 = rand::thread_rng();
    rng1.gen::<u8>()
}

#[allow(dead_code)]
pub fn random_bytes(n: usize) -> Vec<u8> {
    (0..n).map(|_| rand_u8()).collect::<Vec<u8>>()
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

pub fn inplace_xor(mut a: Vec<u8>, b: &[u8]) -> Vec<u8> {
    for i in 0..a.len() {
        a[i] = a[i] ^ b[i];
    }
    a
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
    let padding_bytes = blocksize - (bytes.len() % blocksize);
    let new_len = bytes.len() + padding_bytes;
    bytes.resize(new_len, padding_bytes as u8);
    bytes
}

pub fn unpad(mut bytes: Vec<u8>) -> Vec<u8> {
    let num_padding_bytes = bytes.pop();
    match num_padding_bytes {
        Some(n) => {
            // already removed one above...
            let new_len = bytes.len() + 1 - n as usize;
            bytes.resize(new_len, 0);
            bytes
        }
        None => bytes,
    }
}

pub fn valid_padding(bytes: &[u8], blocksize: usize) -> bool {
    let bytes_len = bytes.len();
    if bytes_len % blocksize != 0 {
        return false;
    }
    let pad_value = bytes[bytes_len - 1];
    if pad_value > blocksize as u8 {
        return false;
    }
    ((bytes_len - (pad_value as usize))..(bytes_len - 1))
        .map(|i| bytes[i])
        .all(|v| v == pad_value)
}

// from 0-1, what percentage of blocks in ciphertext are unique
pub fn percent_unique_blocks(blocksize: usize, ciphertext: &[u8]) -> f32 {
    let mut unique_blocks = 0;
    let numblocks = ciphertext.len() / blocksize;
    for i in 0..numblocks {
        let mut is_unique = true;
        for j in 0..numblocks {
            if j == i {
                continue;
            }

            if ciphertext[(i * blocksize)..((i + 1) * blocksize)] ==
               ciphertext[(j * blocksize)..((j + 1) * blocksize)] {
                is_unique = false;
                break;
            }
        }
        if is_unique {
            unique_blocks = unique_blocks + 1;
        }
    }

    (unique_blocks as f32) / (numblocks as f32)
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
    assert_eq!([1, 2, 3, 4, 5, 6, 7, 8, 8, 8, 8, 8, 8, 8, 8, 8],
               pad(vec![1, 2, 3, 4, 5, 6, 7, 8], 8).as_slice());

    let unpadded = vec![1, 2, 3, 4, 5];
    assert_eq!(unpadded, unpad(pad(unpadded.clone(), 8)));
}

#[test]
fn test_unique() {
    assert_eq!(0.0, percent_unique_blocks(1, &vec![0, 0, 0]));
    assert_eq!(1.0, percent_unique_blocks(1, &vec![0, 1, 2]));
    assert_eq!(0.5, percent_unique_blocks(1, &vec![0, 1, 2, 2]));
}

#[test]
fn test_valid_padding() {
    for blocksize in [8, 16, 32].iter() {
        for _ in 0..1000 {
            let len = rand_u8() as usize;
            let bytes = random_bytes(len);
            let padded = pad(bytes, *blocksize);
            assert!(valid_padding(&padded, *blocksize));
        }
    }
}
