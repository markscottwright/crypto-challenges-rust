mod bytes;
mod hexstring;
mod aes;
mod challenge3;
mod challenge4;
mod challenge6;
mod challenge7;
mod challenge8;
mod challenge9;
mod challenge10;
mod challenge11;
mod challenge12;
mod challenge13;

extern crate base64;
extern crate crypto;
extern crate rand;

use std::time::Instant;

// macro to put a header and footer around a challenge
macro_rules! challenge {
    ($x:ident) => (
        println!("===== begin: {} =====", stringify!($x));
        let start = Instant::now();
        $x::$x();
        let stop = start.elapsed();
        println!("{} seconds",
            stop.as_secs() as f32 + (stop.subsec_nanos() as f32 / 1_000_000_000f32));
        println!("===== end:   {} =====", stringify!($x));
        println!("");
        );
}

fn main() {
    challenge!(challenge3);
    challenge!(challenge4);
    challenge!(challenge6);
    challenge!(challenge7);
    challenge!(challenge8);
    challenge!(challenge9);
    challenge!(challenge10);
    challenge!(challenge11);
    challenge!(challenge12);
    challenge!(challenge13);
}
