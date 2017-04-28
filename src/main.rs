mod bytes;
mod hexstring;
mod aes;
mod challenge3;
mod challenge4;
mod challenge6;
mod challenge7;
mod challenge8;

extern crate base64;
extern crate crypto;

use std::time::{Instant, Duration};

macro_rules! challenge {
    ($x:ident) => (
        println!("===== begin: {} =====", stringify!($x));
        let start = Instant::now();
        $x::$x();
        let stop = start.elapsed();
        println!("{} seconds",
            stop.as_secs() as f32 + (stop.subsec_nanos() as f32 / 1_000_000_000f32));
        println!("===== end:   {} =====", stringify!($x));
        );
}

fn main() {
    challenge!(challenge3);
    challenge!(challenge4);
    challenge!(challenge6);
    challenge!(challenge7);
    challenge!(challenge8);
}
