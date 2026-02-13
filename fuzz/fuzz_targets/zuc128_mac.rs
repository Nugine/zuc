#![no_main]

use libfuzzer_sys::fuzz_target;
use zuc::zuc128::Zuc128Mac;

fuzz_target!(|data: &[u8]| {
    if data.len() < 32 {
        return;
    }

    let ik: [u8; 16] = data[0..16].try_into().unwrap();
    let iv: [u8; 16] = data[16..32].try_into().unwrap();
    let msg = &data[32..];

    // Test with full byte-aligned message
    let _ = Zuc128Mac::compute(&ik, &iv, msg, msg.len() * 8);

    // Test streaming API
    let mut mac = Zuc128Mac::new(&ik, &iv);
    if msg.len() > 1 {
        mac.update(&msg[..msg.len() / 2]);
        let _ = mac.finish(&msg[msg.len() / 2..], (msg.len() - msg.len() / 2) * 8);
    } else {
        let _ = mac.finish(msg, msg.len() * 8);
    }
});
