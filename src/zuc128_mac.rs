use crate::mac::{MacCore, MacKeyPair};
use crate::zuc128::Zuc128Core;

use stdx::default::default;

/// ZUC128 MAC generation algorithm
/// ([GB/T 33133.3-2021](http://c.gb688.cn/bzgk/gb/showGb?type=online&hcno=C6D60AE0A7578E970EF2280ABD49F4F0))
///
/// Input:
/// - `ik`:         128bit  integrity key
/// - `iv`:         128bit  initial vector
/// - `length`:     32bit   The number of bits to be encrypted/decrypted.
/// - `m`:          the input message
///
/// Output:
/// - `u32`:        MAC(Message Authentication Code)
///
/// # Panics
/// + Panics if `length` is greater than the bit length of `m`
/// + Panics if `length` is greater than `usize::MAX`.
#[allow(clippy::cast_possible_truncation)]
#[must_use]
pub fn zuc128_generate_mac(ik: &[u8; 16], iv: &[u8; 16], length: u32, m: &[u8]) -> u32 {
    let bitlen = usize::try_from(length).expect("`length` is greater than `usize::MAX`");
    Zuc128Mac::compute(ik, iv, m, bitlen)
}

/// ZUC128 MAC generator
/// ([GB/T 33133.3-2021](http://c.gb688.cn/bzgk/gb/showGb?type=online&hcno=C6D60AE0A7578E970EF2280ABD49F4F0))
pub struct Zuc128Mac(MacCore<Zuc128Core, u32>);

impl Zuc128Mac {
    /// Create a new ZUC128 MAC generator
    #[must_use]
    pub fn new(ik: &[u8; 16], iv: &[u8; 16]) -> Self {
        let mut zuc = Zuc128Core::new(ik, iv);
        let key = u64::gen_key_pair(&mut zuc);

        Self(MacCore {
            zuc,
            key,
            tag: 0,
            rem: default(),
            cnt: 0,
        })
    }

    /// Update the MAC generator with the bytes of a message
    pub fn update(&mut self, msg: &[u8]) {
        self.0.update(msg);
    }

    /// Finish the MAC generation and return the MAC
    #[allow(clippy::cast_possible_truncation)]
    #[must_use]
    pub fn finish(mut self, tail: &[u8], bitlen: usize) -> u32 {
        let final_bitlen = self.0.finish(tail, bitlen);

        let mut tag = self.0.tag;
        let key = self.0.key;

        tag ^= key.high();

        if final_bitlen == 0 {
            tag ^= key as u32;
        } else {
            tag ^= self.0.zuc.generate();
        }

        tag
    }

    /// Compute the MAC of a message
    #[must_use]
    pub fn compute(ik: &[u8; 16], iv: &[u8; 16], msg: &[u8], bitlen: usize) -> u32 {
        Self::new(ik, iv).finish(msg, bitlen)
    }
}
