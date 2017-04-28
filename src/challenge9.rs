use bytes::pad;

// pkcs7 padding
pub fn challenge9() {
    let mut test_string = b"YELLOW SUBMARINE".to_vec();
    if pad(test_string, 20).as_slice() == b"YELLOW SUBMARINE\x04\x04\x04\x04" {
        println!("Challenge 9 passed");
    } else {
        println!("Challenge 9 failed *************");
    }
}
