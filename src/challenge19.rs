use base64::decode;
use aes::encrypt_ctr;
use std::collections::HashMap;
use std::cmp::min;
use std::sync::Mutex;

lazy_static! {

    // load a set of sorted words into a vector
    static ref SORTED_ENGLISH_WORDS: Vec<&'static str> = {
        // include_str!("google-10000-english-usa-sorted.txt")
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

pub fn byte_histogram(bytes: &[u8]) -> Vec<usize> {
    let mut histogram = vec![0;256];
    for b in bytes {
        histogram[*b as usize] += 1;
    }
    histogram
}

pub fn bytes_by_frequency(histogram: &[usize]) -> Vec<u8> {
    let mut bytes = (0..255).collect::<Vec<u8>>();
    bytes.sort_by_key(|b| histogram[*b as usize]);
    bytes.reverse();
    bytes
        .iter()
        .cloned()
        .filter(|b| histogram[*b as usize] != 0)
        .collect()
}

/*
 * Letter frequency: "etaoinshrdlcumwfgypbvkjxqz"
 * Letter frequency, with punctation and spaces: " et.?-'aoinshrdlcumwfgypbvkjxqz"
 *
 * This is both hard and apparently unnecessary.  But, what we need is something like an iterator
 * that generates possible key bytes, ordered using the histogram, then rates the englishness of the
 * results.
 *
 * Note that we should go through this, creating a list of [[byte -> letter,...], ...].  At each
 * position, the byte->letter should be varied by one, and we should test the resulting cleartexts
 * for "englishness" by splitting on the last whitespace (or punctuation?) and confirming that the
 * tail string is a possible english word's prefix.
 *
 * for pos in 0..longest_ciphertext {
 *  for mapping in mappings(histogram[pos]) {
 *      let good_mapping =
 *      for i in ciphertexts.len() {
 *          if !is_possible_english(cleartexts_so_far[i] + decode(ciphertexts[i][pos], mapping))
 *              break
 *      }
 *  }
 * }
 *
 * fn generate_maps(pos, cleartexts, ciphertexts, mappings_so_far: Vec<Map<byte, char>>) -> Some(Vec<Map<byte, char>>) {
 *  if pos == max_len(ciphertexts)
 *      return mappings_so_far
 *
 *  for mapping in histogram(ciphertexts, pos) {
 *      let mapping_is_good = (0..ciphertexts.len)
 *          .map(|i| isenglish(cleartexts[i] + mapping[ciphertexts[i][pos]]))
 *          .all()
 *      if mapping_is_good {
 *          new_cleartexts = append mapping to cleartexts at pos
 *          new_mappings = mappings_so_far + mapping;
 *          if let Some(full_mapping) = generate_maps(pos, new_cleartexts, ciphertexts, new_mappings) {
 *              return Some(full_mapping)
 *          }
 *      }
 *  }
 *
 *  None
 * }
 *
 */


/*
 *  let x = index_of_longest_ciphertext
 *  fn solve(x, ciphertexts, &mut key) -> Some<key>
 *  {
 *      let i = key.len()
 *      if ciphertexts[x].len() == i {
 *          Some(key.clone())
 *      }
 *
 *      for guess in ordered_characters {
 *          let k = ciphertexts[x][i] ^ c;
 *          key.push(k);
 *          if ciphertexts.iter().map(|c| good_key(key, c)).all() {
 *              if let Some(key2) = solve(x, ciphertexts, key)
 *                  return Some(key2)
 *          }
 *          key.pop(k)
 *      }
 *      None
 *  }
 *
 */

pub fn make_mapping(bytes_by_frequency: &[u8]) -> HashMap<u8, char> {
    let letters_by_freq = "etaoinshrdlcumwfgypbvkjxqz";
    bytes_by_frequency
        .iter()
        .cloned()
        .zip(letters_by_freq.chars())
        .collect::<HashMap<_, _>>()
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
        let rc = last_word_str.len() == 0 || is_number(&last_word_str) || is_english_prefix(&last_word_str);
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

    if let Some(key) = solve_repeated_pad(&ciphertexts, 0, &mut vec![]) {
        println!("key = {:?}", &key);

    //    println!("best answer len = {:?}", BEST_ANSWER.lock().unwrap().len());
    //    let best_key = BEST_ANSWER.lock().unwrap();
        for c in ciphertexts {
            let cleartext = key
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
