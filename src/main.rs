mod bytes;
mod hexstring;
mod aes;
mod challenge3;
mod challenge4;
mod challenge6;
mod challenge7;

extern crate base64;
extern crate crypto;

macro_rules! challenge {
    ($x:ident) => (
        println!("===== begin: {} =====", stringify!($x));
        $x::$x();
        println!("===== end:   {} =====", stringify!($x));
        );
}

fn main() {
    challenge!(challenge3);
    challenge!(challenge4);
    challenge!(challenge6);
    challenge!(challenge7);
}
