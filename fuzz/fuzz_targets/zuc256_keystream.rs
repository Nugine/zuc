#![no_main]

use libfuzzer_sys::fuzz_target;
use zuc::zuc256::Zuc256Keystream;

fuzz_target!(|data: &[u8]| {
    if data.len() < 55 {
        return;
    }

    let key: [u8; 32] = data[0..32].try_into().unwrap();
    let iv: [u8; 23] = data[32..55].try_into().unwrap();

    let mut keystream = Zuc256Keystream::new(&key, &iv);

    // Generate some keystream words to exercise the algorithm
    for _ in 0..16 {
        let _ = keystream.generate();
    }
});
