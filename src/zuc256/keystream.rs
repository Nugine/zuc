use crate::internal::keystream::Keystream;
use crate::internal::zuc::Zuc;

/// d constants
static D: [u8; 16] = [
    0b_0010_0010, //
    0b_0010_1111, //
    0b_0010_0100, //
    0b_0010_1010, //
    0b_0110_1101, //
    0b_0100_0000, //
    0b_0100_0000, //
    0b_0100_0000, //
    0b_0100_0000, //
    0b_0100_0000, //
    0b_0100_0000, //
    0b_0100_0000, //
    0b_0100_0000, //
    0b_0101_0010, //
    0b_0001_0000, //
    0b_0011_0000, //
];

/// concat u8 bits to 31bit u32
fn concat_bits(a: u8, b: u8, c: u8, d: u8) -> u32 {
    (u32::from(a) << 23) | (u32::from(b) << 16) | (u32::from(c) << 8) | u32::from(d)
}

/// ZUC256 keystream generator
/// ([ZUC256-version1.1](http://www.is.cas.cn/ztzl2016/zouchongzhi/201801/W020180416526664982687.pdf))
#[derive(Debug, Clone)]
pub struct Zuc256Keystream {
    /// zuc core
    core: Zuc,
}

impl Zuc256Keystream {
    /// Creates a ZUC256 keystream generator
    #[must_use]
    pub fn new(k: &[u8; 32], iv: &[u8; 23]) -> Self {
        Zuc256Keystream::new_with_d(k, iv, &D)
    }

    /// Creates a [`Zuc256Core`] with specific d constants
    pub(crate) fn new_with_d(k: &[u8; 32], iv: &[u8; 23], d: &[u8; 16]) -> Self {
        let mut zuc = Zuc::zeroed();
        // extend from 184bit iv[0..=22] (u8*23) to iv[0..=24](8bit*17 + 6bit *8)
        let iv17: u8 = iv[17] >> 2;
        let iv18: u8 = ((iv[17] & 0x3) << 4) | (iv[18] >> 4);
        let iv19: u8 = ((iv[18] & 0xf) << 2) | (iv[19] >> 6);
        let iv20: u8 = iv[19] & 0x3f;
        let iv21: u8 = iv[20] >> 2;
        let iv22: u8 = ((iv[20] & 0x3) << 4) | (iv[21] >> 4);
        let iv23: u8 = ((iv[21] & 0xf) << 2) | (iv[22] >> 6);
        let iv24: u8 = iv[22] & 0x3f;

        zuc.s[0] = concat_bits(k[0], d[0], k[21], k[16]);
        zuc.s[1] = concat_bits(k[1], d[1], k[22], k[17]);
        zuc.s[2] = concat_bits(k[2], d[2], k[23], k[18]);
        zuc.s[3] = concat_bits(k[3], d[3], k[24], k[19]);
        zuc.s[4] = concat_bits(k[4], d[4], k[25], k[20]);
        zuc.s[5] = concat_bits(iv[0], d[5] | iv17, k[5], k[26]);
        zuc.s[6] = concat_bits(iv[1], d[6] | iv18, k[6], k[27]);
        zuc.s[7] = concat_bits(iv[10], d[7] | iv19, k[7], iv[2]);
        zuc.s[8] = concat_bits(k[8], d[8] | iv20, iv[3], iv[11]);
        zuc.s[9] = concat_bits(k[9], d[9] | iv21, iv[12], iv[4]);
        zuc.s[10] = concat_bits(iv[5], d[10] | iv22, k[10], k[28]);
        zuc.s[11] = concat_bits(k[11], d[11] | iv23, iv[6], iv[13]);
        zuc.s[12] = concat_bits(k[12], d[12] | iv24, iv[7], iv[14]);
        zuc.s[13] = concat_bits(k[13], d[13], iv[15], iv[8]);
        zuc.s[14] = concat_bits(k[14], d[14] | (k[31] >> 4), iv[16], iv[9]);
        zuc.s[15] = concat_bits(k[15], d[15] | (k[31] & 0b_1111), k[30], k[29]);
        zuc.init();
        Self { core: zuc }
    }

    ///  Generates the next 32-bit word in ZUC256 keystream
    #[must_use]
    pub fn generate(&mut self) -> u32 {
        self.core.generate()
    }
}

impl Keystream for Zuc256Keystream {
    type Word = u32;

    #[inline]
    fn next_key(&mut self) -> Self::Word {
        self.generate()
    }
}

impl Iterator for Zuc256Keystream {
    type Item = u32;

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        Some(self.generate())
    }
}

impl cipher::AlgorithmName for Zuc256Keystream {
    fn write_alg_name(f: &mut core::fmt::Formatter) -> core::fmt::Result {
        write!(f, "Zuc256")
    }
}

impl cipher::KeySizeUser for Zuc256Keystream {
    type KeySize = cipher::typenum::U32;
}

impl cipher::IvSizeUser for Zuc256Keystream {
    type IvSize = cipher::typenum::U23;
}

impl cipher::BlockSizeUser for Zuc256Keystream {
    type BlockSize = cipher::typenum::U4;
}

impl cipher::ParBlocksSizeUser for Zuc256Keystream {
    type ParBlocksSize = cipher::typenum::U1;
}

impl cipher::KeyIvInit for Zuc256Keystream {
    fn new(key: &cipher::Key<Self>, iv: &cipher::Iv<Self>) -> Self {
        Zuc256Keystream::new(key.as_ref(), iv.as_ref())
    }
}

impl cipher::StreamBackend for Zuc256Keystream {
    fn gen_ks_block(&mut self, block: &mut cipher::Block<Self>) {
        let z = self.generate();
        block.copy_from_slice(&z.to_be_bytes());
    }
}

impl cipher::StreamCipherCore for Zuc256Keystream {
    fn remaining_blocks(&self) -> Option<usize> {
        None
    }

    fn process_with_backend(&mut self, f: impl cipher::StreamClosure<BlockSize = Self::BlockSize>) {
        f.call(self);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Examples
    ///
    /// FROM <http://www.is.cas.cn/ztzl2016/zouchongzhi/201801/W020180416526664982687.pdf>
    struct Example {
        k: [u8; 32],
        iv: [u8; 23],
        expected: [u32; 20],
    }

    static EXAMPLE1: Example = Example {
        k: [0; 32],
        iv: [0; 23],
        expected: [
            0x58d0_3ad6,
            0x2e03_2ce2,
            0xdafc_683a,
            0x39bd_cb03,
            0x52a2_bc67,
            0xf1b7_de74,
            0x163c_e3a1,
            0x01ef_5558,
            0x9639_d75b,
            0x95fa_681b,
            0x7f09_0df7,
            0x5639_1ccc,
            0x903b_7612,
            0x744d_544c,
            0x17bc_3fad,
            0x8b16_3b08,
            0x2178_7c0b,
            0x9777_5bb8,
            0x4943_c6bb,
            0xe8ad_8afd,
        ],
    };

    static EXAMPLE2: Example = Example {
        k: [0xff; 32],
        iv: [0xff; 23],
        expected: [
            0x3356_cbae,
            0xd1a1_c18b,
            0x6baa_4ffe,
            0x343f_777c,
            0x9e15_128f,
            0x251a_b65b,
            0x949f_7b26,
            0xef71_57f2,
            0x96dd_2fa9,
            0xdf95_e3ee,
            0x7a5b_e02e,
            0xc32b_a585,
            0x505a_f316,
            0xc2f9_ded2,
            0x7cdb_d935,
            0xe441_ce11,
            0x15fd_0a80,
            0xbb7a_ef67,
            0x6898_9416,
            0xb8fa_c8c2,
        ],
    };

    static ALL_EXAMPLES: &[&Example] = &[&EXAMPLE1, &EXAMPLE2];

    #[test]
    fn examples() {
        for Example { k, iv, expected } in ALL_EXAMPLES {
            let mut zuc = Zuc256Keystream::new(k, iv);
            for i in 0..expected.len() {
                assert_eq!(zuc.generate(), expected[i]);
            }
        }
    }

    #[test]
    fn cipher() {
        use cipher::{Block, KeyIvInit, StreamBackend};

        for Example { k, iv, expected } in ALL_EXAMPLES {
            let mut zuc = <Zuc256Keystream as KeyIvInit>::new(k.into(), iv.into());
            let mut block = Block::<Zuc256Keystream>::default();
            for i in 0..expected.len() {
                zuc.gen_ks_block(&mut block);
                assert_eq!(u32::from_be_bytes(block.into()), expected[i]);
            }
        }
    }
}
