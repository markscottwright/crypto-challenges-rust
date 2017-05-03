use aes::encrypt_cbc;
use bytes::pad;

fn encryptor(userdata: &[u8]) -> Vec<u8> {
    let key = vec![1;16];
    let iv = vec![0;16];
    let prefix = b"comment1=cooking%20MCs;userdata=";
    let suffix = b";comment2=%20like%20a%20pound%20of%20bacon";

    let mut cleartext = Vec::with_capacity(prefix.len() + suffix.len() + userdata.len());
    for b in prefix.iter() {
        cleartext.push(*b);
    }

    // quote userdata
    static AND: u8 = '&' as u8;
    static EQUAL: u8 = '=' as u8;
    for b in userdata {
        if *b == AND {
            cleartext.push('%' as u8);
            cleartext.push('2' as u8);
            cleartext.push('6' as u8);
        }
        else if *b == EQUAL {
            cleartext.push('%' as u8);
            cleartext.push('3' as u8);
            cleartext.push('D' as u8);
        }
        else {
            cleartext.push(*b);
        }
    }

    for b in suffix.iter() {
        cleartext.push(*b);
    }

    encrypt_cbc(&pad(cleartext, 16), &key, &iv).unwrap()
}

pub fn challenge16() {
}

pub fn contains<T>(haystack: &[T], needle: &[T]) -> bool
        where T: PartialEq {
    haystack.windows(needle.len()).any(|w| w == needle)
}

#[test]
fn test() {
    assert!(contains(b"12345", b"12"));
    assert!(contains(b"12345", b"34"));
    assert!(!contains(b"12345", b"125"));
    assert!(!contains(&encryptor(b"abcdedfg"), b"abcdefg"));
}
