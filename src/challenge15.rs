use bytes::valid_padding;

pub fn challenge15() {
    if valid_padding(b"ICE ICE BABY\x04\x04\x04\x04", 16) &&
       !valid_padding(b"ICE ICE BABY\x05\x05\x05\x05", 16) &&
       !valid_padding(b"ICE ICE BABY\x01\x02\x03\x04", 16) {
        println!("passed");
    } else {
        println!("FAILED!!!!");
    }
}
