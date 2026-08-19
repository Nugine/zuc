#![no_main]

use libfuzzer_sys::fuzz_target;
use zuc::zuc256::Zuc256Mac;

fuzz_target!(|data: &[u8]| {
    if data.len() < 55 {
        return;
    }

    let ik: [u8; 32] = data[0..32].try_into().unwrap();
    let iv: [u8; 23] = data[32..55].try_into().unwrap();
    let msg = &data[55..];

    // Test with 32-bit MAC
    let _ = <Zuc256Mac<u32>>::compute(&ik, &iv, msg, msg.len() * 8);

    // Test with 64-bit MAC
    let _ = <Zuc256Mac<u64>>::compute(&ik, &iv, msg, msg.len() * 8);

    // Test with 128-bit MAC
    let _ = <Zuc256Mac<u128>>::compute(&ik, &iv, msg, msg.len() * 8);

    // Test streaming API with 32-bit MAC
    let mut mac = <Zuc256Mac<u32>>::new(&ik, &iv);
    if msg.len() > 1 {
        mac.update(&msg[..msg.len() / 2]);
        let _ = mac.finish(&msg[msg.len() / 2..], (msg.len() - msg.len() / 2) * 8);
    } else {
        let _ = mac.finish(msg, msg.len() * 8);
    }
});
