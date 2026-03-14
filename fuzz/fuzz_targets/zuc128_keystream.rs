#![no_main]

use libfuzzer_sys::fuzz_target;
use zuc::zuc128::Zuc128Keystream;

fuzz_target!(|data: &[u8]| {
    if data.len() < 32 {
        return;
    }

    let key: [u8; 16] = data[0..16].try_into().unwrap();
    let iv: [u8; 16] = data[16..32].try_into().unwrap();

    let mut keystream = Zuc128Keystream::new(&key, &iv);

    // Generate some keystream words to exercise the algorithm
    for _ in 0..16 {
        let _ = keystream.generate();
    }
});
