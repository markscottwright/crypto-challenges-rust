#[derive(Debug, PartialEq)]
pub struct DecodeError;

fn fromhexchar(src: char) -> Result<u8, DecodeError> {
    match src {
        '0'...'9' => Ok((src as u8) - ('0' as u8)),
        'a'...'f' => Ok((src as u8) - ('a' as u8) + 10),
        'A'...'F' => Ok((src as u8) - ('a' as u8) + 10),
        _ => Err(DecodeError),
    }
}

// convert 'hex string' in aabbccdd format into a vec of bytes
pub fn fromhex(src: &str) -> Result<Vec<u8>, DecodeError> {
    let n = src.len() / 2 + src.len() % 2;
    let mut dest = Vec::with_capacity(n);
    let mut src_iter = src.chars();

    // odd-length input - interpret first char as lo-nibble of a half-byte
    if src.len() % 2 == 1 {
        let lonibble = try!(src_iter.next().ok_or(DecodeError));
        let lonibble_decoded = try!(fromhexchar(lonibble));
        dest.push(lonibble_decoded);
    }

    // iterate over every two chars and combine them
    while let Some(hinibble) = src_iter.next() {
        let hinibble_decoded = try!(fromhexchar(hinibble));
        let lonibble = try!(src_iter.next().ok_or(DecodeError));
        let lonibble_decoded = try!(fromhexchar(lonibble));
        dest.push((hinibble_decoded << 4) | lonibble_decoded);
    }

    Ok(dest)
}

#[test]
fn test() {
    assert_eq!(fromhex("aabbccXX"), Err(DecodeError));
    assert_eq!(fromhex("aabbccdd"), Ok(vec![0xaa, 0xbb, 0xcc, 0xdd]));
}
