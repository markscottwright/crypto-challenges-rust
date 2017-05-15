use base64::decode;
use aes::encrypt_ctr;
use std::collections::HashMap;
use std::cmp::min;

lazy_static! {

    // load a set of sorted words into a vector
    static ref SORTED_ENGLISH_WORDS: Vec<&'static str> = {
        include_str!("google-10000-english-usa-sorted.txt")
            .lines()
            .collect::<Vec<_>>()
        };
}

fn is_english_prefix(guess: &str) -> bool {
    let lc_guess = guess.to_lowercase();
    let guess_len = guess.len();
    SORTED_ENGLISH_WORDS
        .binary_search_by(|&w| {
                              let w_len = min(w.len(), guess_len);
                              w.cmp(&lc_guess)
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

    // our decryptions
    let mut cleartexts2: Vec<Vec<char>> = Vec::with_capacity(ciphertexts.len());
    for _ in 0..ciphertexts.len() {
        cleartexts2.push(Vec::new());
    }

    let max_ciphertext_len = ciphertexts.iter().map(|x| x.len()).max().unwrap();
    println!("{:?}", max_ciphertext_len);
    for i in 0..max_ciphertext_len {
        let ith_bytes = ciphertexts
            .iter()
            .filter_map(|x| x.get(i))
            .cloned()
            .collect::<Vec<_>>();
        let histogram = byte_histogram(&ith_bytes);
        let bytes_by_frequency = bytes_by_frequency(&histogram);
        let mapping = make_mapping(&bytes_by_frequency);
        for (ciphertext, mut cleartext) in ciphertexts.iter().zip(cleartexts2.iter_mut()) {
            if let Some(byte) = ciphertext.get(i) {
                cleartext.push(*mapping.get(byte).unwrap());
            }
        }
    }

    for cleartext in cleartexts2 {
        let s: String = cleartext.into_iter().collect();
        println!("{}", s);
    }

}

#[test]
fn test_prefix() {
    assert!(is_english_prefix("a"));
    assert!(is_english_prefix("Az"));
    assert!(!is_english_prefix("zt"));
}
