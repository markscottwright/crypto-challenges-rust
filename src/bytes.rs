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
                 ' ' => 1,
                 '\'' => 1,
                 '\"' => 1,
                 '.' => 1,
                 _ => 0,
             })
        .sum();

    return num_english_chars as f32 / cleartext.len() as f32;
}
