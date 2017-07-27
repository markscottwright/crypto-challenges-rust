pub struct Mt19937 {
    mt: [u32; 624],
    index: usize
}

pub fn init(seed: u32) -> Mt19937 {
    let mut mt = [0u32; 624];
    mt[0] = seed;
    for i in 1..mt.len() {
        mt[i] = 1812433253u32.wrapping_mul(
            (mt[i - 1] ^ mt[i - 1] >> 30) + (i as u32));
    }

    Mt19937 { mt: mt, index: 0 }
}

fn twist(mt: &mut Mt19937) {
    for i in 0..624 {
        let y = (mt.mt[i] & 0x80000000) + (mt.mt[(i + 1) % 624] & 0x7fffffff);
        mt.mt[i] = mt.mt[(i + 397) % 624] ^ y >> 1;

        if y % 2 != 0 {
            mt.mt[i] = mt.mt[i] ^ 0x9908b0df;
        }
    }

    mt.index = 0;
}

pub fn next(mt: &mut Mt19937) -> u32 {
    if mt.index >= 624 {
        twist(mt);
    }

    let mut y = mt.mt[mt.index];
    y = y ^ y >> 11;
    y = y ^ y << 7 & 2636928640;
    y = y ^ y << 15 & 4022730752;
    y = y ^ y >> 18;
    mt.index = mt.index + 1;

    return y;
}

pub fn mt19937() {
    let w = 32;
    const n: usize = 624;
    let m = 397;
    let r = 31;
    let a = 0x9908b0df;
    let u = 11;
    let d = 0xffffffff;
    let s = 7;
    let b = 0x9D2C5680;
    let t = 15;
    let c = 0xEFC60000;
    let l = 18;

    let mt: [u32; n];

}

pub fn challenge21() {
    let mut m = init(0);
    for i in 0..1000000 {
        println!("{}", next(&mut m));
    }

}
