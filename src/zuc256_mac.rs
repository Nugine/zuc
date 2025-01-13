//! ZUC-256 Algorithms MAC generate
use crate::mac::{MacKeyPair, MacWord};
use crate::zuc256::Zuc256Core;

use core::mem::size_of;

/// d constant for 32bit MAC
const D_32: [u8; 16] = [
    0b010_0010, 0b010_1111, 0b010_0101, 0b010_1010, 0b110_1101, 0b100_0000, 0b100_0000, 0b100_0000,
    0b100_0000, 0b100_0000, 0b100_0000, 0b100_0000, 0b100_0000, 0b101_0010, 0b001_0000, 0b011_0000,
];

/// d constant for 64bit MAC
const D_64: [u8; 16] = [
    0b010_0011, 0b010_1111, 0b010_0100, 0b010_1010, 0b110_1101, 0b100_0000, 0b100_0000, 0b100_0000,
    0b100_0000, 0b100_0000, 0b100_0000, 0b100_0000, 0b100_0000, 0b101_0010, 0b001_0000, 0b011_0000,
];

/// d constant for 128bit MAC
const D_128: [u8; 16] = [
    0b010_0011, 0b010_1111, 0b010_0101, 0b010_1010, 0b110_1101, 0b100_0000, 0b100_0000, 0b100_0000,
    0b100_0000, 0b100_0000, 0b100_0000, 0b100_0000, 0b100_0000, 0b101_0010, 0b001_0000, 0b011_0000,
];

/// xor t for zuc 256 mac
#[inline(always)]
fn zuc_256_mac_xor_t<T>(bits: &mut T, key: &mut T::KeyPair, tag: &mut T)
where
    T: MacWord,
{
    if bits.test_high_bit() {
        *tag ^= key.high();
    }
    *bits <<= 1;
    *key <<= 1;
}

/// ZUC256 MAC generation algorithm
/// ([ZUC256-version1.1](http://www.is.cas.cn/ztzl2016/zouchongzhi/201801/W020180416526664982687.pdf))
///
/// Input:
/// - `<T>`:        u32/u64/u128    output MAC type
/// - `ik`:         128bit          integrity key
/// - `iv`:         128bit          initial vector
/// - `length`:     32bit           The number of bits to be encrypted/decrypted.
/// - `m`:          the input message
///
/// Output:
/// - `T`:        MAC(Message Authentication Code)
///
/// # Panics
/// + Panics if `length` is greater than the length of `m`
/// + Panics if `length` is greater than `usize::MAX`.
#[must_use]
#[allow(clippy::cast_possible_truncation)]
pub fn zuc256_generate_mac<T>(ik: &[u8; 32], iv: &[u8; 23], length: u32, m: &[u8]) -> T
where
    T: MacWord,
{
    let bitlen = usize::try_from(length).expect("`length` is greater than `usize::MAX`");
    assert!(
        bitlen <= m.len() * 8,
        "`length` is greater than the length of `m`"
    );

    let byte_size = size_of::<T>();
    let bit_size = byte_size * 8;

    let d = match byte_size {
        4 => &D_32,
        8 => &D_64,
        16 => &D_128,
        _ => unreachable!(),
    };

    let mut zuc = Zuc256Core::new_with_d(ik, iv, d);
    let mut gen = || zuc.generate();

    let mut tag: T = T::gen_word(&mut gen);
    let mut key: T::KeyPair = T::KeyPair::gen_key_pair(&mut gen);

    for chunk in m[..(bitlen / 8)].chunks_exact(byte_size) {
        let mut bits = T::from_chunk(chunk);

        for _ in 0..bit_size {
            zuc_256_mac_xor_t(&mut bits, &mut key, &mut tag);
        }

        key.set_low(T::gen_word(&mut gen));
    }

    if bitlen % bit_size != 0 {
        let mut bits = {
            let i = bitlen / bit_size * byte_size;
            let j = (bitlen % bit_size - 1) / 8;

            let mut buf = [0u8; 16];
            buf[..=j].copy_from_slice(&m[i..=i + j]);
            <T>::from_chunk(&buf[..byte_size])
        };

        for _ in 0..(bitlen % bit_size) {
            zuc_256_mac_xor_t(&mut bits, &mut key, &mut tag);
        }
    }

    tag ^= key.high();

    tag
}

#[cfg(test)]
mod tests {
    use super::*;

    // examples from http://www.is.cas.cn/ztzl2016/zouchongzhi/201801/W020180416526664982687.pdf
    struct ExampleMAC {
        k: [u8; 32],
        iv: [u8; 23],
        length: u32,
        m: &'static [u8],
        expected_32: u32,
        expected_64: u64,
        expected_128: u128,
    }

    static EXAMPLE_MAC_1: ExampleMAC = ExampleMAC {
        k: [0; 32],
        iv: [0; 23],
        length: 400,
        m: &[0; 50],
        expected_32: 0x9b97_2a74,
        expected_64: 0x673e_5499_0034_d38c,
        expected_128: 0xd85e_54bb_cb96_0096_7084_c952_a165_4b26,
    };

    static EXAMPLE_MAC_2: ExampleMAC = ExampleMAC {
        k: [0; 32],
        iv: [0; 23],
        length: 4000,
        m: &[0x11; 500],
        expected_32: 0x8754_f5cf,
        expected_64: 0x130d_c225_e722_40cc,
        expected_128: 0xdf1e_8307_b31c_c62b_eca1_ac6f_8190_c22f,
    };

    static EXAMPLE_MAC_3: ExampleMAC = ExampleMAC {
        k: [0xff; 32],
        iv: [0xff; 23],
        length: 400,
        m: &[0x00; 50],
        expected_32: 0x1f30_79b4,
        expected_64: 0x8c71_394d_3995_7725,
        expected_128: 0xa35b_b274_b567_c48b_2831_9f11_1af3_4fbd,
    };

    static EXAMPLE_MAC_4: ExampleMAC = ExampleMAC {
        k: [0xff; 32],
        iv: [0xff; 23],
        length: 4000,
        m: &[0x11; 500],
        expected_32: 0x5c7c_8b88,
        expected_64: 0xea1d_ee54_4bb6_223b,
        expected_128: 0x3a83_b554_be40_8ca5_4941_24ed_9d47_3205,
    };

    #[test]
    fn examples_mac() {
        let examples = [
            &EXAMPLE_MAC_1,
            &EXAMPLE_MAC_2,
            &EXAMPLE_MAC_3,
            &EXAMPLE_MAC_4,
        ];

        for x in examples {
            let mac_32 = zuc256_generate_mac::<u32>(&x.k, &x.iv, x.length, x.m);
            assert_eq!(mac_32, x.expected_32);

            let mac_64 = zuc256_generate_mac::<u64>(&x.k, &x.iv, x.length, x.m);
            assert_eq!(mac_64, x.expected_64);

            let mac_128 = zuc256_generate_mac::<u128>(&x.k, &x.iv, x.length, x.m);
            assert_eq!(mac_128, x.expected_128);
        }
    }

    #[test]
    fn special_bitlen() {
        let x = &EXAMPLE_MAC_2;
        let bitlen = 145;
        let mac_32 = zuc256_generate_mac::<u32>(&x.k, &x.iv, bitlen, x.m);
        let expected_32 = 0x213e_1ce5; // generated from GmSSL
        assert_eq!(mac_32, expected_32, "actual = {mac_32:08x}");
    }

    #[test]
    fn zero_bitlen() {
        let examples = [&EXAMPLE_MAC_1, &EXAMPLE_MAC_2];

        for x in examples {
            let bitlen = 0;
            let mac_32 = zuc256_generate_mac::<u32>(&x.k, &x.iv, bitlen, x.m);
            let expected_32 = 0x68dc_aaba; // generated from GmSSL
            assert_eq!(mac_32, expected_32, "actual = {mac_32:08x}");
        }
    }
}
