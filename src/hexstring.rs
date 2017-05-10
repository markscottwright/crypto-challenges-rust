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

#[allow(dead_code)]
pub fn tohex(src: &[u8]) -> String {
    let mut dest = String::with_capacity(src.len() * 2);
    for b in src {
        dest.push(match b & 0xf0 {
                      0x00 => '0',
                      0x10 => '1',
                      0x20 => '2',
                      0x30 => '3',
                      0x40 => '4',
                      0x50 => '5',
                      0x60 => '6',
                      0x70 => '7',
                      0x80 => '8',
                      0x90 => '9',
                      0xa0 => 'a',
                      0xb0 => 'b',
                      0xc0 => 'c',
                      0xd0 => 'd',
                      0xe0 => 'e',
                      0xf0 => 'f',
                      _ => panic!("numbers no longer working"),
                  });
        dest.push(match b & 0xf {
                      0x0 => '0',
                      0x1 => '1',
                      0x2 => '2',
                      0x3 => '3',
                      0x4 => '4',
                      0x5 => '5',
                      0x6 => '6',
                      0x7 => '7',
                      0x8 => '8',
                      0x9 => '9',
                      0xa => 'a',
                      0xb => 'b',
                      0xc => 'c',
                      0xd => 'd',
                      0xe => 'e',
                      0xf => 'f',
                      _ => panic!("numbers no longer working"),
                  });
    }
    dest
}

#[test]
fn test() {
    assert_eq!(fromhex("aabbccXX"), Err(DecodeError));
    assert_eq!(fromhex("aabbccdd"), Ok(vec![0xaa, 0xbb, 0xcc, 0xdd]));
    assert_eq!(tohex(&fromhex("aabbccdd").unwrap()), "aabbccdd");
}
