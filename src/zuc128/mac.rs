use super::Zuc128Keystream;

use crate::internal::mac::{MacCore, MacKeyPair, MacWord};

use numeric_cast::TruncatingCast;
use stdx::default::default;

/// ZUC128 MAC generator
/// ([GB/T 33133.3-2021](http://c.gb688.cn/bzgk/gb/showGb?type=online&hcno=C6D60AE0A7578E970EF2280ABD49F4F0))
pub struct Zuc128Mac(MacCore<Zuc128Keystream, u32>);

impl Zuc128Mac {
    /// Compute the MAC of a message
    ///
    /// ## Input
    /// | name   | size     | description                     |
    /// | ------ | -------- | ------------------------------- |
    /// | ik     | 128 bits | integrity key                   |
    /// | iv     | 128 bits | initial vector                  |
    /// | msg    | -        | the input message               |
    /// | bitlen | -        | bit length of the input message |
    ///
    /// ## Output
    /// 32 bits MAC (Message Authentication Code)
    #[must_use]
    pub fn compute(ik: &[u8; 16], iv: &[u8; 16], msg: &[u8], bitlen: usize) -> u32 {
        Self::new(ik, iv).finish(msg, bitlen)
    }

    /// Create a new ZUC128 MAC generator
    #[must_use]
    pub fn new(ik: &[u8; 16], iv: &[u8; 16]) -> Self {
        let mut zuc = Zuc128Keystream::new(ik, iv);
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
    #[must_use]
    pub fn finish(mut self, tail: &[u8], bitlen: usize) -> u32 {
        let final_bitlen = self.0.finish(tail, bitlen);

        let mut tag = self.0.tag;
        let key = self.0.key;

        tag ^= key.high();

        if final_bitlen == 0 {
            tag ^= key.truncating_cast::<u32>();
        } else {
            tag ^= self.0.zuc.generate();
        }

        tag
    }
}

impl digest::Update for Zuc128Mac {
    fn update(&mut self, data: &[u8]) {
        Zuc128Mac::update(self, data);
    }
}

impl digest::OutputSizeUser for Zuc128Mac {
    type OutputSize = digest::typenum::U4;
}

impl digest::FixedOutput for Zuc128Mac {
    fn finalize_into(self, out: &mut digest::Output<Self>) {
        let tag = self.finish(&[], 0);
        *out = tag.to_be_array();
    }
}

impl digest::MacMarker for Zuc128Mac {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_digest() {
        fn require_digest_mac<T: digest::Mac>() {}

        require_digest_mac::<Zuc128Mac>();
    }
}
