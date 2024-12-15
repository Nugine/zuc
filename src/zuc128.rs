//! ZUC-128 Algorithms

/// d constants
const D: [u32; 16] = [
    0b_0100_0100_1101_0111_0000_0000,
    0b_0010_0110_1011_1100_0000_0000,
    0b_0110_0010_0110_1011_0000_0000,
    0b_0001_0011_0101_1110_0000_0000,
    0b_0101_0111_1000_1001_0000_0000,
    0b_0011_0101_1110_0010_0000_0000,
    0b_0111_0001_0011_0101_0000_0000,
    0b_0000_1001_1010_1111_0000_0000,
    0b_0100_1101_0111_1000_0000_0000,
    0b_0010_1111_0001_0011_0000_0000,
    0b_0110_1011_1100_0100_0000_0000,
    0b_0001_1010_1111_0001_0000_0000,
    0b_0101_1110_0010_0110_0000_0000,
    0b_0011_1100_0100_1101_0000_0000,
    0b_0111_1000_1001_1010_0000_0000,
    0b_0100_0111_1010_1100_0000_0000,
];

/// S0 box
const S0: [u8; 256] = const_str::hex!([
    "3E 72 5B 47 CA E0 00 33 04 D1 54 98 09 B9 6D CB",
    "7B 1B F9 32 AF 9D 6A A5 B8 2D FC 1D 08 53 03 90",
    "4D 4E 84 99 E4 CE D9 91 DD B6 85 48 8B 29 6E AC",
    "CD C1 F8 1E 73 43 69 C6 B5 BD FD 39 63 20 D4 38",
    "76 7D B2 A7 CF ED 57 C5 F3 2C BB 14 21 06 55 9B",
    "E3 EF 5E 31 4F 7F 5A A4 0D 82 51 49 5F BA 58 1C",
    "4A 16 D5 17 A8 92 24 1F 8C FF D8 AE 2E 01 D3 AD",
    "3B 4B DA 46 EB C9 DE 9A 8F 87 D7 3A 80 6F 2F C8",
    "B1 B4 37 F7 0A 22 13 28 7C CC 3C 89 C7 C3 96 56",
    "07 BF 7E F0 0B 2B 97 52 35 41 79 61 A6 4C 10 FE",
    "BC 26 95 88 8A B0 A3 FB C0 18 94 F2 E1 E5 E9 5D",
    "D0 DC 11 66 64 5C EC 59 42 75 12 F5 74 9C AA 23",
    "0E 86 AB BE 2A 02 E7 67 E6 44 A2 6C C2 93 9F F1",
    "F6 FA 36 D2 50 68 9E 62 71 15 3D D6 40 C4 E2 0F",
    "8E 83 77 6B 25 05 3F 0C 30 EA 70 B7 A1 E8 A9 65",
    "8D 27 1A DB 81 B3 A0 F4 45 7A 19 DF EE 78 34 60",
]);

/// S1 box
const S1: [u8; 256] = const_str::hex!([
    "55 C2 63 71 3B C8 47 86 9F 3C DA 5B 29 AA FD 77",
    "8C C5 94 0C A6 1A 13 00 E3 A8 16 72 40 F9 F8 42",
    "44 26 68 96 81 D9 45 3E 10 76 C6 A7 8B 39 43 E1",
    "3A B5 56 2A C0 6D B3 05 22 66 BF DC 0B FA 62 48",
    "DD 20 11 06 36 C9 C1 CF F6 27 52 BB 69 F5 D4 87",
    "7F 84 4C D2 9C 57 A4 BC 4F 9A DF FE D6 8D 7A EB",
    "2B 53 D8 5C A1 14 17 FB 23 D5 7D 30 67 73 08 09",
    "EE B7 70 3F 61 B2 19 8E 4E E5 4B 93 8F 5D DB A9",
    "AD F1 AE 2E CB 0D FC F4 2D 46 6E 1D 97 E8 D1 E9",
    "4D 37 A5 75 5E 83 9E AB 82 9D B9 1C E0 CD 49 89",
    "01 B6 BD 58 24 A2 5F 38 78 99 15 90 50 B8 95 E4",
    "D0 91 C7 CE ED 0F B4 6F A0 CC F0 02 4A 79 C3 DE",
    "A3 EF EA 51 E6 6B 18 EC 1B 2C 80 F7 74 E7 FF 21",
    "5A 6A 54 1E 41 31 92 35 C4 33 07 0A BA 7E 0E 34",
    "88 B1 98 7C F3 3D 60 6C 7B CA D3 1F 32 65 04 28",
    "64 BE 85 9B 2F 59 8A D7 B0 25 AC AF 12 03 E2 F2",
]);

use cipher::consts::{U1, U16, U4};
use cipher::{
    AlgorithmName, Block, BlockSizeUser, Iv, IvSizeUser, Key, KeyIvInit, KeySizeUser,
    ParBlocksSizeUser, StreamBackend, StreamCipherCore, StreamCipherCoreWrapper, StreamClosure,
};

/// [`StreamCipherCore`] implementation for ZUC-128
pub struct Zuc128Core {
    /// LFSR registers S0 to S15
    s: [u32; 16],
    /// memory cells R1 and R2
    r: [u32; 2],
}

impl Zuc128Core {
    /// function `LFSRWithInitialisationMode`
    fn lfsr_with_init_mode(&mut self, u: u32) {
        let mut sum = [
            u64::from(self.s[15]) << 15,
            u64::from(self.s[13]) << 17,
            u64::from(self.s[10]) << 21,
            u64::from(self.s[4]) << 20,
            u64::from(self.s[0]) << 8,
            u64::from(self.s[0]),
            u64::from(u),
        ]
        .into_iter()
        .sum::<u64>();
        sum = (sum >> 31) + (sum % (1 << 31)); // <= 2^32 - 2
        sum = (sum >> 31) + (sum % (1 << 31)); // <= 2^31 - 1
        for i in 0..15 {
            self.s[i] = self.s[i + 1];
        }
        self.s[15] = u32::try_from(sum).unwrap(); // this never panics as sum <= 2^31 - 1
    }

    /// function `LFSRWithWorkMode`
    fn lfsr_with_work_mode(&mut self) {
        self.lfsr_with_init_mode(0);
    }

    /// function `BitReorganisation`
    const fn bit_reorganization(&self) -> [u32; 4] {
        [
            ((self.s[15] << 1) & 0xffff_0000) | self.s[14] & 0xffff,
            self.s[11] << 16 | self.s[9] >> 15,
            self.s[7] << 16 | self.s[5] >> 15,
            self.s[2] << 16 | self.s[0] >> 15,
        ]
    }

    /// S-box
    const fn s(x: u32) -> u32 {
        let bytes = x.to_le_bytes();
        let bytes = [
            S1[bytes[0] as usize],
            S0[bytes[1] as usize],
            S1[bytes[2] as usize],
            S0[bytes[3] as usize],
        ];
        u32::from_le_bytes(bytes)
    }

    /// linear transform L1
    const fn l1(x: u32) -> u32 {
        x ^ x.rotate_left(2) ^ x.rotate_left(10) ^ x.rotate_left(18) ^ x.rotate_left(24)
    }

    /// linear transform L2
    const fn l2(x: u32) -> u32 {
        x ^ x.rotate_left(8) ^ x.rotate_left(14) ^ x.rotate_left(22) ^ x.rotate_left(30)
    }

    /// nonlinear function F
    fn f(&mut self, x: [u32; 3]) -> u32 {
        let w = (x[0] ^ self.r[0]).wrapping_add(self.r[1]);
        let w1 = self.r[0].wrapping_add(x[1]);
        let w2 = self.r[1] ^ x[2];
        self.r[0] = Self::s(Self::l1(w1 << 16 | w2 >> 16));
        self.r[1] = Self::s(Self::l2(w2 << 16 | w1 >> 16));
        w
    }
}

impl AlgorithmName for Zuc128Core {
    fn write_alg_name(f: &mut core::fmt::Formatter) -> core::fmt::Result {
        write!(f, "ZUC-128")
    }
}

impl KeySizeUser for Zuc128Core {
    type KeySize = U16;
}

impl IvSizeUser for Zuc128Core {
    type IvSize = U16;
}

impl KeyIvInit for Zuc128Core {
    fn new(key: &Key<Self>, iv: &Iv<Self>) -> Self {
        let mut s = D;
        s.iter_mut().zip(key).zip(iv).for_each(|((s, &k), &i)| {
            *s |= u32::from(k) << 23;
            *s |= u32::from(i);
        });
        let mut zuc = Self { s, r: [0, 0] };
        for _ in 0..32 {
            let x = zuc.bit_reorganization();
            let w = zuc.f([x[0], x[1], x[2]]);
            zuc.lfsr_with_init_mode(w >> 1);
        }
        let x = zuc.bit_reorganization();
        zuc.f([x[0], x[1], x[2]]);
        // put off the `LFSRWithWorkMode()` in the specification to the first key stream generation
        zuc
    }
}

impl BlockSizeUser for Zuc128Core {
    type BlockSize = U4;
}

impl ParBlocksSizeUser for Zuc128Core {
    type ParBlocksSize = U1;
}

impl StreamBackend for Zuc128Core {
    fn gen_ks_block(&mut self, block: &mut Block<Self>) {
        // This is moved from the end (as in the specification) to the beginning
        // to save one `LFSRWithWorkMode()`
        self.lfsr_with_work_mode();
        let x = self.bit_reorganization();
        let z = self.f([x[0], x[1], x[2]]) ^ x[3];
        block.copy_from_slice(&z.to_be_bytes());
    }
}

impl StreamCipherCore for Zuc128Core {
    fn remaining_blocks(&self) -> Option<usize> {
        None
    }

    fn process_with_backend(&mut self, f: impl StreamClosure<BlockSize = Self::BlockSize>) {
        f.call(self);
    }
}

/// [`StreamCipher`][cipher::StreamCipher] implementation for ZUC-128
pub type Zuc128 = StreamCipherCoreWrapper<Zuc128Core>;

#[cfg(test)]
mod tests {
    use super::*;

    // https://www.gsma.com/solutions-and-impact/technologies/security/wp-content/uploads/2019/05/eea3eia3testdatav11.pdf

    struct TestSet {
        key: [u8; 16],
        iv: [u8; 16],
        output: Vec<Option<u32>>,
    }

    impl TestSet {
        fn run(&self) {
            let mut core = Zuc128Core::new(&self.key.into(), &self.iv.into());
            let mut block = Block::<Zuc128Core>::default();
            for o in &self.output {
                core.gen_ks_block(&mut block);
                if let Some(o) = o {
                    assert_eq!(block, o.to_be_bytes().into());
                }
            }
        }
    }

    #[test]
    fn test_set_1() {
        TestSet {
            key: [0; 16],
            iv: [0; 16],
            output: vec![Some(0x27be_de74), Some(0x0180_82da)],
        }
        .run();
    }

    #[test]
    fn test_set_2() {
        TestSet {
            key: [0xff; 16],
            iv: [0xff; 16],
            output: vec![Some(0x0657_cfa0), Some(0x7096_398b)],
        }
        .run();
    }

    #[test]
    fn test_set_3() {
        TestSet {
            key: [
                0x3d, 0x4c, 0x4b, 0xe9, 0x6a, 0x82, 0xfd, 0xae, 0xb5, 0x8f, 0x64, 0x1d, 0xb1, 0x7b,
                0x45, 0x5b,
            ],
            iv: [
                0x84, 0x31, 0x9a, 0xa8, 0xde, 0x69, 0x15, 0xca, 0x1f, 0x6b, 0xda, 0x6b, 0xfb, 0xd8,
                0xc7, 0x66,
            ],
            output: vec![Some(0x14f1_c272), Some(0x3279_c419)],
        }
        .run();
    }

    #[test]
    fn test_set_4() {
        let mut output = vec![None; 2000];
        output[0] = Some(0xed44_00e7);
        output[1] = Some(0x0633_e5c5);
        output[1999] = Some(0x7a57_4cdb);
        TestSet {
            key: [
                0x4d, 0x32, 0x0b, 0xfa, 0xd4, 0xc2, 0x85, 0xbf, 0xd6, 0xb8, 0xbd, 0x00, 0xf3, 0x9d,
                0x8b, 0x41,
            ],
            iv: [
                0x52, 0x95, 0x9d, 0xab, 0xa0, 0xbf, 0x17, 0x6e, 0xce, 0x2d, 0xc3, 0x15, 0x04, 0x9e,
                0xb5, 0x74,
            ],
            output,
        }
        .run();
    }
}
