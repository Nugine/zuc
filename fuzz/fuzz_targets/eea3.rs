#![no_main]

use libfuzzer_sys::fuzz_target;
use zuc::eea3::eea3_xor_inplace;

fuzz_target!(|data: &[u8]| {
    if data.len() < 22 {
        return;
    }

    let count = u32::from_be_bytes(data[0..4].try_into().unwrap());
    let bearer = data[4];
    let direction = data[5];
    let ck: [u8; 16] = data[6..22].try_into().unwrap();
    let plaintext = &data[22..];

    if plaintext.is_empty() {
        return;
    }

    let mut buf = plaintext.to_vec();
    let bitlen = buf.len() * 8;

    // Encrypt
    eea3_xor_inplace(count, bearer, direction, &ck, &mut buf, bitlen);

    // Decrypt (XOR is symmetric)
    eea3_xor_inplace(count, bearer, direction, &ck, &mut buf, bitlen);

    // Verify roundtrip
    assert_eq!(buf, plaintext);
});
