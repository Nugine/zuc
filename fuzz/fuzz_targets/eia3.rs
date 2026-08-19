#![no_main]

use libfuzzer_sys::fuzz_target;
use zuc::eia3::Eia3Mac;

fuzz_target!(|data: &[u8]| {
    if data.len() < 22 {
        return;
    }

    let count = u32::from_be_bytes(data[0..4].try_into().unwrap());
    let bearer = data[4];
    let direction = data[5];
    let ik: [u8; 16] = data[6..22].try_into().unwrap();
    let msg = &data[22..];

    // Test with full byte-aligned message
    let _ = Eia3Mac::compute(count, bearer, direction, &ik, msg, msg.len() * 8);

    // Test streaming API
    let mut mac = Eia3Mac::new(count, bearer, direction, &ik);
    if msg.len() > 1 {
        mac.update(&msg[..msg.len() / 2]);
        let _ = mac.finish(&msg[msg.len() / 2..], (msg.len() - msg.len() / 2) * 8);
    } else {
        let _ = mac.finish(msg, msg.len() * 8);
    }
});
