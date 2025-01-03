//! ZUC shared implementation

use crate::utils::{add, rol};

/// S0 box
static S0: [u8; 256] = const_str::hex!([
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
static S1: [u8; 256] = const_str::hex!([
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

/// L1 linear transform
#[inline(always)]
fn l1(x: u32) -> u32 {
    x ^ rol(x, 2) ^ rol(x, 10) ^ rol(x, 18) ^ rol(x, 24)
}

/// L2 linear transform
#[inline(always)]
fn l2(x: u32) -> u32 {
    x ^ rol(x, 8) ^ rol(x, 14) ^ rol(x, 22) ^ rol(x, 30)
}

/// S box transform
#[inline(always)]
fn sbox(x: u32) -> u32 {
    let x = x.to_be_bytes();
    let y = [
        S0[x[0] as usize],
        S1[x[1] as usize],
        S0[x[2] as usize],
        S1[x[3] as usize],
    ];
    u32::from_be_bytes(y)
}

/// ZUC keystream generator
#[derive(Clone, Debug)]
pub(crate) struct Zuc {
    /// LFSR registers (31-bit words x16)
    pub s: [u32; 16],

    /// R1 state unit (32 bits)
    pub r1: u32,

    /// R2 state unit (32 bits)
    pub r2: u32,
}

impl Zuc {
    /// Zero-initialized
    pub fn zeroed() -> Self {
        Self {
            s: [0; 16],
            r1: 0,
            r2: 0,
        }
    }

    /// Creates a ZUC128 keystream generator
    pub fn init(&mut self) {
        for _ in 0..32 {
            let x = self.bit_reconstruction();
            let w = self.f(x);
            self.lfsr_with_initialization_mode(w >> 1);
        }

        {
            let x = self.bit_reconstruction();
            self.f(x);
        }
    }

    /// `BitReconstruction` function
    fn bit_reconstruction(&mut self) -> [u32; 4] {
        let Self { s, .. } = self;
        let x0 = ((s[15] & 0x7FFF_8000) << 1) | (s[14] & 0xFFFF);
        let x1 = ((s[11] & 0xFFFF) << 16) | (s[9] >> 15);
        let x2 = ((s[7] & 0xFFFF) << 16) | (s[5] >> 15);
        let x3 = ((s[2] & 0xFFFF) << 16) | (s[0] >> 15);
        [x0, x1, x2, x3]
    }

    /// F non-linear function
    fn f(&mut self, x: [u32; 4]) -> u32 {
        let Self { r1, r2, .. } = self;

        let w = add(x[0] ^ (*r1), *r2);
        let w1 = add(*r1, x[1]);
        let w2 = (*r2) ^ x[2];
        *r1 = sbox(l1((w1 << 16) | (w2 >> 16)));
        *r2 = sbox(l2((w2 << 16) | (w1 >> 16)));

        w
    }

    /// `LFSRWithInitialisationMode` function
    #[allow(clippy::cast_possible_truncation)]
    fn lfsr_with_initialization_mode(&mut self, u: u32) {
        let Self { s, .. } = self;

        // standard:
        // v = (2^15 * s[15] + 2^17 * s[13] + 2^21 * s[10] + 2^20 * s[4] + (1+2^8) * s[0]) mod (2^31 - 1)
        // s[16] = (v + u) mod (2^31 - 1)
        // if s[16] == 0 { s[16] = 2^31 - 1 }
        //
        // equivalent to:
        // NOTE: s[i] is a 31-bit word
        // sum = 2^15 * s[15] + 2^17 * s[13] + 2^21 * s[10] + 2^20 * s[4] + (1+2^8) * s[0] + u
        // NOTE: sum <= 2^53 - 1
        //
        // NOTE: (2^31) * x + y ≡ x + y (mod (2^31 - 1))
        // sum = (sum >> 31) + (sum % (1<<31))
        // NOTE: sum <= (2^22 - 1) + (2^31 - 1) <= (2^32 - 2)
        //
        // sum = (sum >> 31) + (sum % (1<<31))
        // NOTE: sum <= 0 + (2^31 - 1)
        //       sum <= 1 + (2^31 - 2)
        //       sum <= 2^31 - 1
        //
        // if sum == 2^31 - 1 {
        //     (v + u) mod (2^31 - 1) == 0
        //     s[16] = sum = 2^31 - 1
        // } else {
        //     (v + u) mod (2^31 - 1) == sum
        //     s[16] = sum
        // }
        //
        // equivalent to:
        // s[16] = sum

        let s16 = {
            let mut sum = u64::from(u);
            sum += u64::from(s[0]);
            sum += u64::from(s[0]) << 8;
            sum += u64::from(s[4]) << 20;
            sum += u64::from(s[10]) << 21;
            sum += u64::from(s[13]) << 17;
            sum += u64::from(s[15]) << 15;

            sum = (sum >> 31) + (sum & ((1 << 31) - 1));
            let mut sum = sum as u32;
            sum = (sum >> 31) + (sum & ((1 << 31) - 1));

            sum
        };

        for i in 0..15 {
            s[i] = s[i + 1];
        }
        s[15] = s16;
    }

    /// `LFSRWithWorkMode` function
    pub fn lfsr_with_work_mode(&mut self) {
        self.lfsr_with_initialization_mode(0);
    }

    /// Generates the next 32-bit word in ZUC128 keystream
    pub fn generate(&mut self) -> u32 {
        self.lfsr_with_work_mode();
        let x = self.bit_reconstruction();
        self.f(x) ^ x[3]
    }
}

/// trait convertible from bytes for zuc remaining bits
pub trait ZucFromBytes: Sized {
    /// get remaining bits for zuc from message
    fn get_zuc_remaining_bits(bitlen: usize, m: &[u8]) -> Self;
    /// type size
    const T_SIZE: usize;
    /// type byte size
    const T_BYTE_SIZE: usize;
}

impl ZucFromBytes for u32 {
    fn get_zuc_remaining_bits(bitlen: usize, m: &[u8]) -> Self {
        let i = bitlen / Self::T_SIZE * Self::T_BYTE_SIZE;
        let j = (bitlen % Self::T_SIZE - 1) / 8;
        let mut bytes = [0u8; 4];
        bytes[..=j].copy_from_slice(&m[i..=i + j]);
        Self::from_be_bytes(bytes)
    }
    const T_SIZE: usize = 32;
    const T_BYTE_SIZE: usize = 4;
}

impl ZucFromBytes for u64 {
    fn get_zuc_remaining_bits(bitlen: usize, m: &[u8]) -> Self {
        let i = bitlen / Self::T_SIZE * Self::T_BYTE_SIZE;
        let j = (bitlen % Self::T_SIZE - 1) / 8;
        let mut bytes = [0u8; 8];
        bytes[..=j].copy_from_slice(&m[i..=i + j]);
        Self::from_be_bytes(bytes)
    }
    const T_SIZE: usize = 64;
    const T_BYTE_SIZE: usize = 8;
}

impl ZucFromBytes for u128 {
    fn get_zuc_remaining_bits(bitlen: usize, m: &[u8]) -> Self {
        let i = bitlen / Self::T_SIZE * Self::T_BYTE_SIZE;
        let j = (bitlen % Self::T_SIZE - 1) / 8;
        let mut bytes = [0u8; 16];
        bytes[..=j].copy_from_slice(&m[i..=i + j]);
        Self::from_be_bytes(bytes)
    }
    const T_SIZE: usize = 128;
    const T_BYTE_SIZE: usize = 16;
}
