//! ZUC-128 Algorithms

use crate::zuc::Zuc;

/// d constants 128
pub static D_128: [u16; 16] = [
    0b_0100_0100_1101_0111,
    0b_0010_0110_1011_1100,
    0b_0110_0010_0110_1011,
    0b_0001_0011_0101_1110,
    0b_0101_0111_1000_1001,
    0b_0011_0101_1110_0010,
    0b_0111_0001_0011_0101,
    0b_0000_1001_1010_1111,
    0b_0100_1101_0111_1000,
    0b_0010_1111_0001_0011,
    0b_0110_1011_1100_0100,
    0b_0001_1010_1111_0001,
    0b_0101_1110_0010_0110,
    0b_0011_1100_0100_1101,
    0b_0111_1000_1001_1010,
    0b_0100_0111_1010_1100,
];

/// ZUC128 keystream generator
/// ([GB/T 33133.1-2016](https://openstd.samr.gov.cn/bzgk/gb/newGbInfo?hcno=8C41A3AEECCA52B5C0011C8010CF0715))
#[derive(Debug, Clone)]
pub struct Zuc128 {
    /// zuc core
    core: Zuc,
}

impl Zuc128 {
    /// Creates a ZUC128 keystream generator
    #[must_use]
    pub fn new(key: &[u8; 16], iv: &[u8; 16]) -> Self {
        let mut zuc = Zuc::zeroed();
        for i in 0..16 {
            let k_i = u32::from(key[i]);
            let d_i = u32::from(D_128[i]);
            let iv_i = u32::from(iv[i]);
            zuc.s[i] = (k_i << 23) | (d_i << 8) | iv_i;
        }
        zuc.init();
        Self { core: zuc }
    }

    ///  Generates the next 32-bit word in ZUC128 keystream
    pub fn generate(&mut self) -> u32 {
        self.core.generate()
    }
}

impl Iterator for Zuc128 {
    type Item = u32;

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        Some(self.generate())
    }
}

#[cfg(test)]
mod tests {
    use crate::Zuc128;

    // examples from http://c.gb688.cn/bzgk/gb/showGb?type=online&hcno=8C41A3AEECCA52B5C0011C8010CF0715
    struct Example {
        k: [u8; 16],
        iv: [u8; 16],
        expected: [[u32; 8]; 3],
    }

    static EXAMPLE1: Example = Example {
        k: [0; 16],
        iv: [0; 16],
        expected: [
            [
                0x7c37_ba6b,
                0xb136_7f6c,
                0x1e42_6568,
                0xdd0b_f9c2,
                0x3512_bf50,
                0xa092_0453,
                0x286d_afe5,
                0x7f08_e141,
            ],
            [
                0xfe11_8d6a,
                0xd452_2c3a,
                0xe955_463d,
                0x4c2b_e8f9,
                0xc7ee_7f13,
                0x0c0f_a817,
                0x27be_de74,
                0x3d38_3d04,
            ],
            [
                0x7a70_e141,
                0x9a74_e229,
                0x071e_62e2,
                0xc82e_c4b3,
                0xdde6_3da7,
                0xb9dd_6a41,
                0x0180_82da,
                0x13d6_d780,
            ],
        ],
    };

    static EXAMPLE2: Example = Example {
        k: [0xff; 16],
        iv: [0xff; 16],
        expected: [
            [
                0x3fc8_1ce8,
                0xc2d1_41d1,
                0x4bd0_8879,
                0x4227_1346,
                0xaa13_1b11,
                0x09d7_706c,
                0x668b_56df,
                0x13f5_6dbf,
            ],
            [
                0x27ea_6106,
                0x82c8_f4b6,
                0x0b14_d499,
                0x9187_2523,
                0x251e_7804,
                0xcaac_5d66,
                0x0657_cfa0,
                0x0c0f_e353,
            ],
            [
                0x181f_6dbf,
                0x04a2_1879,
                0xf24c_93c6,
                0x773b_4aaa,
                0xd94e_9228,
                0x91d8_8fba,
                0x7096_398b,
                0x10f1_eecf,
            ],
        ],
    };

    static EXAMPLE3: Example = Example {
        k: [
            0x3d, 0x4c, 0x4b, 0xe9, 0x6a, 0x82, 0xfd, 0xae, //
            0xb5, 0x8f, 0x64, 0x1d, 0xb1, 0x7b, 0x45, 0x5b, //
        ],
        iv: [
            0x84, 0x31, 0x9a, 0xa8, 0xde, 0x69, 0x15, 0xca, //
            0x1f, 0x6b, 0xda, 0x6b, 0xfb, 0xd8, 0xc7, 0x66, //
        ],
        expected: [
            [
                0xf534_2a57,
                0x6e20_ef69,
                0x5d6a_8f32,
                0x0ce1_21b4,
                0x129d_8b39,
                0x2d7c_dce1,
                0x3ead_461d,
                0x3d4a_a9e7,
            ],
            [
                0x7a95_1cff,
                0x40b9_2b65,
                0x0a37_4ea7,
                0x8174_b6d5,
                0xab7c_f688,
                0xc159_8aa6,
                0x14f1_c272,
                0x71db_1828,
            ],
            [
                0xe3b6_a9e7,
                0x5503_49fe,
                0xaf31_e6ee,
                0x385a_2e0c,
                0x3cec_1a4a,
                0x9053_cc0e,
                0x3279_c419,
                0x2589_37da,
            ],
        ],
    };

    #[test]
    fn examples() {
        for Example { k, iv, expected } in [&EXAMPLE1, &EXAMPLE2, &EXAMPLE3] {
            let mut zuc = Zuc128::new(k, iv);

            assert_eq!(zuc.core.x, expected[0][..4]);
            assert_eq!(zuc.core.r1, expected[0][4]);
            assert_eq!(zuc.core.r2, expected[0][5]);
            assert_eq!(zuc.core.s[15], expected[0][7]);

            let z1 = zuc.generate();

            assert_eq!(zuc.core.x, expected[1][..4]);
            assert_eq!(zuc.core.r1, expected[1][4]);
            assert_eq!(zuc.core.r2, expected[1][5]);
            assert_eq!(z1, expected[1][6]);
            assert_eq!(zuc.core.s[15], expected[1][7]);

            let z2 = zuc.generate();

            assert_eq!(zuc.core.x, expected[2][..4]);
            assert_eq!(zuc.core.r1, expected[2][4]);
            assert_eq!(zuc.core.r2, expected[2][5]);
            assert_eq!(z2, expected[2][6]);
            assert_eq!(zuc.core.s[15], expected[2][7]);
        }
    }
}
