//! ZUC-256 Algorithms MAC generate
use crate::mac::{MacCore, MacKeyPair, MacWord};
use crate::zuc256::Zuc256Core;

use core::mem::size_of;

use stdx::default::default;

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
/// + Panics if `length` is greater than the bit length of `m`
/// + Panics if `length` is greater than `usize::MAX`.
#[must_use]
pub fn zuc256_generate_mac<T: MacTag>(ik: &[u8; 32], iv: &[u8; 23], length: u32, m: &[u8]) -> T {
    let bitlen = usize::try_from(length).expect("`length` is greater than `usize::MAX`");
    Zuc256Mac::compute(ik, iv, m, bitlen)
}

pub trait MacTag: MacWord {}
impl MacTag for u32 {}
impl MacTag for u64 {}
impl MacTag for u128 {}

/// ZUC256 MAC generator
/// ([ZUC256-version1.1](http://www.is.cas.cn/ztzl2016/zouchongzhi/201801/W020180416526664982687.pdf))
pub struct Zuc256Mac<T: MacTag>(MacCore<Zuc256Core, T>);

impl<T: MacTag> Zuc256Mac<T> {
    /// Create a new ZUC256 MAC generator
    #[must_use]
    pub fn new(ik: &[u8; 32], iv: &[u8; 23]) -> Self {
        let d = match size_of::<T>() {
            4 => &D_32,
            8 => &D_64,
            16 => &D_128,
            _ => unreachable!(),
        };

        let mut zuc = Zuc256Core::new_with_d(ik, iv, d);
        let tag: T = T::gen_word(&mut zuc);
        let key: T::KeyPair = T::KeyPair::gen_key_pair(&mut zuc);

        Self(MacCore {
            zuc,
            key,
            tag,
            rem: default(),
            cnt: 0,
        })
    }

    /// Update the MAC generator with the bytes of a message
    pub fn update(&mut self, msg: &[u8]) {
        self.0.update(msg);
    }

    /// Finish the MAC generation and return the MAC
    pub fn finish(mut self, tail: &[u8], bitlen: usize) -> T {
        let _ = self.0.finish(tail, bitlen);
        self.0.tag ^= self.0.key.high();
        self.0.tag
    }

    /// Compute the MAC of a message
    #[must_use]
    pub fn compute(ik: &[u8; 32], iv: &[u8; 23], msg: &[u8], bitlen: usize) -> T {
        Self::new(ik, iv).finish(msg, bitlen)
    }
}

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

impl<T: MacTag> digest::Update for Zuc256Mac<T> {
    fn update(&mut self, data: &[u8]) {
        Zuc256Mac::update(self, data);
    }
}

impl<T: MacTag> digest::OutputSizeUser for Zuc256Mac<T> {
    type OutputSize = <T as MacWord>::ByteSize;
}

impl<T: MacTag> digest::FixedOutput for Zuc256Mac<T> {
    fn finalize_into(self, out: &mut digest::Output<Self>) {
        let tag = self.finish(&[], 0);
        *out = tag.to_be_array();
    }
}

impl<T: MacTag> digest::MacMarker for Zuc256Mac<T> {}

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

    static ALL_EXAMPLES: &[&ExampleMAC] = &[
        &EXAMPLE_MAC_1,
        &EXAMPLE_MAC_2,
        &EXAMPLE_MAC_3,
        &EXAMPLE_MAC_4,
    ];

    #[test]
    fn examples_mac() {
        for x in ALL_EXAMPLES {
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

    #[test]
    fn streaming() {
        fn check<T: MacTag>(x: &ExampleMAC, parts: &[usize], expected: T) {
            let mut mac = Zuc256Mac::<T>::new(&x.k, &x.iv);

            for i in 1..parts.len() {
                mac.update(&x.m[parts[i - 1]..parts[i]]);
            }

            let last = parts[parts.len() - 1];
            let ans = mac.finish(&x.m[last..], x.length as usize - last * 8);

            assert_eq!(ans, expected);
        }

        for x in ALL_EXAMPLES {
            for bp in 0..(x.length as usize) / 8 {
                check(x, &[0, bp], x.expected_32);
                check(x, &[0, bp], x.expected_64);
                check(x, &[0, bp], x.expected_128);
            }
        }

        for x in ALL_EXAMPLES {
            for bp1 in 0..16 {
                for bp2 in 16..32 {
                    check(x, &[0, bp1, bp2], x.expected_32);
                    check(x, &[0, bp1, bp2], x.expected_64);
                    check(x, &[0, bp1, bp2], x.expected_128);
                }
            }
        }
    }

    #[test]
    fn test_digest() {
        fn require_digest_mac<T: digest::Mac>() {}

        require_digest_mac::<Zuc256Mac<u32>>();
        require_digest_mac::<Zuc256Mac<u64>>();
        require_digest_mac::<Zuc256Mac<u128>>();
    }
}
