//! ZUC-256 Algorithms

use super::zuc::Zuc;

/// d constants
pub static D_256: [u8; 16] = [
    0b010_0010, 0b010_1111, 0b010_0100, 0b010_1010, 0b110_1101, 0b100_0000, 0b100_0000, 0b100_0000,
    0b100_0000, 0b100_0000, 0b100_0000, 0b100_0000, 0b100_0000, 0b101_0010, 0b001_0000, 0b011_0000,
];

/// mac 32bit
#[allow(unused_variables, dead_code)]
pub static MAC_256_32: [u8; 16] = [
    0b010_0010, 0b010_1111, 0b010_0101, 0b010_1010, 0b110_1101, 0b100_0000, 0b100_0000, 0b100_0000,
    0b100_0000, 0b100_0000, 0b100_0000, 0b100_0000, 0b100_0000, 0b101_0010, 0b001_0000, 0b011_0000,
];

/// mac 64bit
#[allow(unused_variables, dead_code)]
pub static MAC_256_64: [u8; 16] = [
    0b010_0011, 0b010_1111, 0b010_0100, 0b010_1010, 0b110_1101, 0b100_0000, 0b100_0000, 0b100_0000,
    0b100_0000, 0b100_0000, 0b100_0000, 0b100_0000, 0b100_0000, 0b101_0010, 0b001_0000, 0b011_0000,
];

/// mac 128bit
#[allow(unused_variables, dead_code)]
pub static MAC_256_128: [u8; 16] = [
    0b010_0011, 0b010_1111, 0b010_0101, 0b010_1010, 0b110_1101, 0b100_0000, 0b100_0000, 0b100_0000,
    0b100_0000, 0b100_0000, 0b100_0000, 0b100_0000, 0b100_0000, 0b101_0010, 0b001_0000, 0b011_0000,
];

/// mac length
pub enum MacLength {
    /// 32 bit
    Bit32,
    /// 64 bit
    Bit64,
    /// 128 bit
    Bit128,
}

/// concat u8 bits to 31bit u32
fn concat_bits(parts: &[u8]) -> u32 {
    let mut result: u32 = 0;
    for (i, &part) in parts.iter().enumerate() {
        let width = if i == 1 { 7 } else { 8 }; // 判断是 7 位 (D) 还是 8 位 (K/IV)
        result = (result << width) | u32::from(part);
    }
    result & 0x7FFF_FFFF // 确保结果为 31 位
}

/// ZUC256 keystream generator
/// [ZUC256-version1.1](http://www.is.cas.cn/ztzl2016/zouchongzhi/201801/W020180416526664982687.pdf)
#[derive(Debug, Clone)]
pub struct Zuc256 {
    /// zuc core
    core: Zuc,
}

impl Zuc256 {
    /// Creates a ZUC256 keystream generator
    #[must_use]
    pub fn new(k: &[u8; 32], iv: &[u8; 25]) -> Self {
        let mut zuc = Zuc::zeroed();
        let d = D_256;
        zuc.s[0] = concat_bits(&[k[0], d[0], k[21], k[16]]);
        zuc.s[1] = concat_bits(&[k[1], d[1], k[22], k[17]]);
        zuc.s[2] = concat_bits(&[k[2], d[2], k[23], k[18]]);
        zuc.s[3] = concat_bits(&[k[3], d[3], k[24], k[19]]);
        zuc.s[4] = concat_bits(&[k[4], d[4], k[25], k[20]]);
        zuc.s[5] = concat_bits(&[iv[0], (d[5] | iv[17]), k[5], k[26]]);
        zuc.s[6] = concat_bits(&[iv[1], (d[6] | iv[18]), k[6], k[27]]);
        zuc.s[7] = concat_bits(&[iv[10], (d[7] | iv[19]), k[7], iv[2]]);
        zuc.s[8] = concat_bits(&[k[8], (d[8] | iv[20]), iv[3], iv[11]]);
        zuc.s[9] = concat_bits(&[k[9], (d[9] | iv[21]), iv[12], iv[4]]);
        zuc.s[10] = concat_bits(&[iv[5], (d[10] | iv[22]), k[10], k[28]]);
        zuc.s[11] = concat_bits(&[k[11], (d[11] | iv[23]), iv[6], iv[13]]);
        zuc.s[12] = concat_bits(&[k[12], (d[12] | iv[24]), iv[7], iv[14]]);
        zuc.s[13] = concat_bits(&[k[13], d[13], iv[15], iv[8]]);
        zuc.s[14] = concat_bits(&[k[14], (d[14] | (k[31] >> 4)), iv[16], iv[9]]);
        zuc.s[15] = concat_bits(&[k[15], (d[15] | (k[31] & 0b_1111)), k[30], k[29]]);
        zuc.init();
        Self { core: zuc }
    }

    ///  Generates the next 32-bit word in ZUC256 keystream
    pub fn generate(&mut self) -> u32 {
        self.core.generate()
    }
}

impl Iterator for Zuc256 {
    type Item = u32;

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        Some(self.generate())
    }
}

#[cfg(test)]
mod tests {
    use crate::Zuc256;

    // examples from http://www.is.cas.cn/ztzl2016/zouchongzhi/201801/W020180416526664982687.pdf
    struct Example {
        k: [u8; 32],
        iv: [u8; 25],
        expected: [u32; 20],
    }

    static EXAMPLE1: Example = Example {
        k: [0; 32],
        iv: [0; 25],
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
        iv: [0xff; 25],
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

    #[test]
    fn unit_test_256() {
        for Example { k, iv, expected } in [&EXAMPLE1, &EXAMPLE2] {
            let mut zuc = Zuc256::new(k, iv);
            for i in 0..20 {
                assert_eq!(zuc.generate(), expected[i]);
            }
        }
    }
}
