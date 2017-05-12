use base64::decode;
use aes::decrypt_ctr;

pub fn challenge18() {
    let ciphertext = decode("L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY\
                            /2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==")
            .unwrap();
    let key = b"YELLOW SUBMARINE";
    let cleartext = decrypt_ctr(&ciphertext, key, &0).unwrap();

    println!("{}", String::from_utf8_lossy(&cleartext));
}
