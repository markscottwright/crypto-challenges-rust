use base64::{decode_config, MIME};
use aes::decrypt_ecb;

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

pub fn challenge8() {
    for (i, line) in include_str!("challenge-1-8.dat").lines().enumerate() {
        let ciphertext = decode_config(line, MIME).unwrap();
        if percent_unique_blocks(16, &ciphertext) < 0.99 {
            println!("{} {} {:?}",
                     i,
                     percent_unique_blocks(16, &ciphertext),
                     line);
        }
    }
}

#[test]
fn test_unique() {
    assert_eq!(0.0, percent_unique_blocks(1, &vec![0, 0, 0]));
    assert_eq!(1.0, percent_unique_blocks(1, &vec![0, 1, 2]));
    assert_eq!(0.5, percent_unique_blocks(1, &vec![0, 1, 2, 2]));
}
