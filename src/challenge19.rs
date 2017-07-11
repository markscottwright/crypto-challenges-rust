use base64::decode;
use aes::encrypt_ctr;
use std::cmp::min;
use std::sync::Mutex;

lazy_static! {

    // load a set of sorted words into a vector
    static ref SORTED_ENGLISH_WORDS: Vec<&'static str> = {
        //include_str!("google-10000-english-usa-sorted.txt")
        include_str!("words-sorted.txt")
            .lines()
            .collect::<Vec<_>>()
        };

    static ref BEST_ANSWER: Mutex<Vec<u8>> = Mutex::new(vec![]);
}

fn is_number(guess: &str) -> bool {
    let numbers = "0123456789";

    guess.chars().all(|c| numbers.contains(c))
}

fn is_english_word(guess: &str) -> bool {
    let lc_guess = guess.to_lowercase();
    SORTED_ENGLISH_WORDS
        .binary_search_by(|&w| {w.cmp(&lc_guess)})
        .is_ok()
}

fn is_english_prefix(guess: &str) -> bool {
    let lc_guess = guess.to_lowercase();
    let guess_len = guess.len();
    SORTED_ENGLISH_WORDS
        .binary_search_by(|&w| {
                              let w_len = min(w.len(), guess_len);
                              w[..w_len].cmp(&lc_guess)
                          })
        .is_ok()
}

fn is_valid_character(byte: &u8) -> bool {
    b"etaoinshrdlcumwfgypbvkjxqz 0123456789-'?:;.,!\"&ETAOINSHRDLCUMWFGYPBVKJXQZ".contains(byte)
}

fn is_space_or_punctuation(byte: &u8) -> bool {
    b" -?:;.,!\"\'&".contains(byte)
}

fn is_valid_word_character(byte: &u8) -> bool {
    b"etaoinshrdlcumwfgypbvkjxqz0123456789ETAOINSHRDLCUMWFGYPBVKJXQZ".contains(byte)
}

fn good_key_so_far(key_so_far: &[u8], ciphertext: &[u8]) -> bool {

    let cleartext = key_so_far
        .iter()
        .zip(ciphertext.iter())
        .map(|(a, b)| a ^ b)
        .collect::<Vec<_>>();

    // is the last byte of cleartext ascii?
    let last_letter = cleartext.last().unwrap();

    if !is_valid_character(&last_letter) {
        return false;
    } else if is_space_or_punctuation(&last_letter) {
        // We just added a word divider.  Check the word before to confirm its
        // an actual word.
        let mut last_word = cleartext
            .iter()
            .rev()
            .skip(1)
            .take_while(|x| is_valid_word_character(x))
            .map(|&x| x as char)
            .collect::<Vec<_>>();
        last_word.reverse();

        // multiple spaces, or an actual word
        let last_word_str: String = last_word.into_iter().collect();
        let rc = last_word_str.len() == 0 || is_number(&last_word_str) || is_english_word(&last_word_str);
        return rc;
    } else {
        // in the middle of a word - is the word we building a possible word?
        let mut last_word = cleartext
            .iter()
            .rev()
            .take_while(|x| is_valid_word_character(x))
            .map(|&x| x as char)
            .collect::<Vec<_>>();
        last_word.reverse();
        let last_word_str: String = last_word.into_iter().collect();

        let rc = is_number(&last_word_str) || is_english_prefix(&last_word_str);
        return rc;
    }
}

fn solve_repeated_pad(ciphertexts: &Vec<Vec<u8>>,
                      target_index: usize,
                      key_so_far: &mut Vec<u8>)
                      -> Option<Vec<u8>> {
    let i = key_so_far.len();

    // key is as long as the target ciphertext - we're done
    if ciphertexts[target_index].len() == i {
        return Some(key_so_far.clone());
    }

    // first letter is more likely uppercase
    let letters_by_freq = match i {
        0 => "ETAOINSHRDLCUMWFGYPBVKJXQZetaoinshrdlcumwfgypbvkjxqz 0123456789'\"?.,!",
        _ => "etaoinshrdlcumwfgypbvkjxqz 0123456789'\"?.,!ETAOINSHRDLCUMWFGYPBVKJXQZ",
    };

    for guess in letters_by_freq.chars() {
        let key_byte = ciphertexts[target_index][i] ^ (guess as u8);
        key_so_far.push(key_byte);
        if ciphertexts
               .iter()
               .all(|c| good_key_so_far(key_so_far, c)) {

            // keep track of our best solution out-of-band
            if key_so_far.len() > BEST_ANSWER.lock().unwrap().len() {
                *(BEST_ANSWER.lock().unwrap()) = key_so_far.clone();
            }

            if let Some(answer) = solve_repeated_pad(ciphertexts, target_index, key_so_far) {
                return Some(answer);
            }
        }
        key_so_far.pop();
    }

    None
}

// Note: because all the cleartexts are not the same length, and we're being very permissive with
// what constitutes a "word", the ends of the longest ciphertexts are harder to find.  The challenge
// said specifically "don't overthink this", so good enough.
pub fn challenge19() {
    let key = b"YELLOW SUBMARINE";
    let nonce = 0;
    let cleartexts = include_str!("challenge-19.dat")
        .lines()
        .map(|x| decode(x).unwrap())
        .collect::<Vec<_>>();
    let ciphertexts = cleartexts
        .iter()
        .map(|cleartext| encrypt_ctr(cleartext, key, &nonce).unwrap())
        .collect::<Vec<_>>();

    let mut max_len = 0;
    let mut longest_ciphertext = 0;
    for i in 0..ciphertexts.len() {
        if ciphertexts[i].len() > max_len {
            max_len = ciphertexts[i].len();
            longest_ciphertext = i;
        }
    }

    if let Some(key) = solve_repeated_pad(&ciphertexts, longest_ciphertext, &mut vec![]) {
        println!("key = {:?}", &key);
        for c in ciphertexts {
            let cleartext = key
                .iter()
                .zip(c.iter())
                .map(|(a, b)| a ^ b)
                .collect::<Vec<_>>();
            println!("{:?}", String::from_utf8_lossy(&cleartext));
        }
    }
    else {
        println!("Didn't find a solution.  Best we did:");

        for c in ciphertexts {
            let cleartext = BEST_ANSWER.lock().unwrap()
                .iter()
                .zip(c.iter())
                .map(|(a, b)| a ^ b)
                .collect::<Vec<_>>();
            println!("{:?}", String::from_utf8_lossy(&cleartext));
        }
    }
}

#[test]
fn test_prefix() {
    assert!(is_english_prefix("a"));
    assert!(is_english_prefix("Az"));
    assert!(is_english_prefix("Ei"));
    assert!(!is_english_prefix("zt"));
}
