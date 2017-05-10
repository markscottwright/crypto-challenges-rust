use std::collections::HashMap;

use crypto::symmetriccipher;
use bytes::{pad, unpad};
use aes::{encrypt_ecb, decrypt_ecb};

fn encrypt(data: &[u8]) -> Vec<u8> {
    let key = [1u8; 16];

    let mut cleartext = data.iter().cloned().collect::<Vec<u8>>();
    cleartext = pad(cleartext, key.len());
    encrypt_ecb(&cleartext, &key).unwrap()
}

fn decrypt(ciphertext: &[u8])
           -> Result<HashMap<String, String>, symmetriccipher::SymmetricCipherError> {

    let key = [1u8; 16];
    let cleartext = try!(decrypt_ecb(ciphertext, &key));
    Ok(parse_cookie(&String::from_utf8_lossy(&unpad(cleartext))))
}

fn oracle(email: &str) -> Vec<u8> {
    encrypt(profile_for(email).as_bytes())
}

fn parse_cookie(cookie: &str) -> HashMap<String, String> {
    cookie
        .split('&')
        .filter_map(|f| {

            let key_and_value: Vec<_> = f.split('=').collect();
            if key_and_value.len() == 2 && key_and_value[0] != "" {
                Some((key_and_value[0].to_string(), key_and_value[1].to_string()))
            } else {
                // can't parse - so just ignore
                None
            }
        })
        .collect()
}

fn strip_metas(s: &str) -> String {
    s.chars().filter(|x| *x != '=' && *x != '&').collect()
}

fn profile_for(email: &str) -> String {
    return format!("email={}&uid=10&role=user", strip_metas(email));
}

pub fn challenge13() {
    let block_size = 16;

    // |123456789012345|123456789012345
    // email=1@3456789.adminBBBBBBBBBBB
    let username1_bytes = b"1@3456789.admin\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b";
    println!("{}", username1_bytes.len() % block_size);
    println!("{}", block_size - (username1_bytes.len() % block_size));
    let username1 = String::from_utf8_lossy(username1_bytes);
    let block_starting_with_admin = &oracle(&username1)[block_size..(block_size * 2)];

    // |123456789012345|123456789012345|123456789012345|123456789012345
    // email=mwright1234567890@example.com&uid=10&role=
    let username2 = "mwright1234567890@example.com";
    let blocks_ending_with_role = &oracle(&username2)[0..(block_size * 3)];

    let attack = blocks_ending_with_role
        .iter()
        .chain(block_starting_with_admin.iter())
        .cloned()
        .collect::<Vec<u8>>();
    let attack_profile = decrypt(&attack);
    println!("{:?}", attack_profile);
}

#[test]
fn test() {
    assert!(parse_cookie("a=b&name=hello").contains_key("a"));
    assert!(parse_cookie("a=b&name=hello").contains_key("name"));
    assert_eq!(parse_cookie("a=b&name=hello").len(), 2);
    assert_eq!(parse_cookie("a=b&invalid&name=hello").len(), 2);
    assert_eq!(parse_cookie("a=b&=invalid&name=hello").len(), 2);
    assert_eq!(profile_for("mwright@example.com"),
               "email=mwright@example.com&uid=10&role=user");
    assert!(!String::from_utf8_lossy(
        &oracle("mwright@example.com")).contains("mwright@example.com"));
    assert!(decrypt(&oracle("mwright@example.com"))
                .unwrap()
                .contains_key("email"));
}
