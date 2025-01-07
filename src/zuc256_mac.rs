//! ZUC-256 Algorithms MAC generate
use crate::u256::U256;
use crate::zuc256::Zuc256Core;

mod private {
    //! private for sealed trait

    use std::ops::BitAnd;
    use std::ops::BitOrAssign;
    use std::ops::BitXor;
    use std::ops::BitXorAssign;
    use std::ops::ShlAssign;

    /// Mac Word
    pub trait MacWord
    where
        Self: Sized + Copy,
        Self: BitXor + BitXorAssign + BitAnd<Output = Self> + BitOrAssign,
        Self: ShlAssign<usize>,
        Self: From<u8>,
        Self: Eq,
    {
        /// Mac Key Pair Type
        type KeyPair: MacKeyPair<Word = Self>;
        /// byte size
        const BYTE_SIZE: usize = std::mem::size_of::<Self>();
        /// bit size
        const BIT_SIZE: usize = std::mem::size_of::<Self>() * 8;
        /// high bit
        const HIGH_BIT: Self;
        /// d constants
        const D: [u8; 16];

        /// generate word
        fn gen_word(zuc: &mut impl FnMut() -> u32) -> Self;

        /// generate key from chunk
        fn from_chunk(chunk: &[u8]) -> Self;

        /// Test the highest bit of the word
        fn test_high_bit(&self) -> bool {
            (*self & Self::HIGH_BIT) != Self::from(0)
        }

        /// Shift left by one bit
        fn shl_once(&mut self) {
            *self <<= 1;
        }
    }

    /// Mac Key Pair
    pub trait MacKeyPair
    where
        Self: Sized + Copy,
        Self: ShlAssign<usize>,
    {
        /// Mac Word Type
        type Word: MacWord<KeyPair = Self>;

        /// generate key pair
        fn gen_key_pair(zuc: &mut impl FnMut() -> u32) -> Self;

        /// get high bits
        fn high(&self) -> Self::Word;

        /// set low bits
        fn set_low(&mut self, low: Self::Word);

        /// Shift left by one bit
        fn shl_once(&mut self) {
            *self <<= 1;
        }
    }
}

use self::private::MacKeyPair;
use self::private::MacWord;

// 32 bit word
impl MacWord for u32 {
    type KeyPair = u64;
    const D: [u8; 16] = [
        0b010_0010, 0b010_1111, 0b010_0101, 0b010_1010, 0b110_1101, 0b100_0000, 0b100_0000,
        0b100_0000, 0b100_0000, 0b100_0000, 0b100_0000, 0b100_0000, 0b100_0000, 0b101_0010,
        0b001_0000, 0b011_0000,
    ];
    const HIGH_BIT: u32 = 1 << (std::mem::size_of::<Self>() * 8 - 1);
    fn gen_word(zuc: &mut impl FnMut() -> u32) -> u32 {
        zuc()
    }
    fn from_chunk(chunk: &[u8]) -> u32 {
        u32::from_be_bytes(chunk[0..Self::BYTE_SIZE].try_into().expect("impossible"))
    }
}

impl MacKeyPair for u64 {
    type Word = u32;
    fn gen_key_pair(zuc: &mut impl FnMut() -> u32) -> u64 {
        u64::from(zuc()) << 32 | u64::from(zuc())
    }

    fn high(&self) -> u32 {
        (self >> 32) as u32
    }
    fn set_low(&mut self, low: Self::Word) {
        *self |= Self::from(low);
    }
}

// 64 bit word
impl MacWord for u64 {
    type KeyPair = u128;
    const D: [u8; 16] = [
        0b010_0011, 0b010_1111, 0b010_0100, 0b010_1010, 0b110_1101, 0b100_0000, 0b100_0000,
        0b100_0000, 0b100_0000, 0b100_0000, 0b100_0000, 0b100_0000, 0b100_0000, 0b101_0010,
        0b001_0000, 0b011_0000,
    ];
    const HIGH_BIT: u64 = 1 << (std::mem::size_of::<Self>() * 8 - 1);
    fn gen_word(zuc: &mut impl FnMut() -> u32) -> u64 {
        (u64::from(zuc()) << 32) | u64::from(zuc())
    }
    fn from_chunk(chunk: &[u8]) -> u64 {
        u64::from_be_bytes(chunk[0..Self::BYTE_SIZE].try_into().expect("impossible"))
    }
}
impl MacKeyPair for u128 {
    type Word = u64;
    fn gen_key_pair(zuc: &mut impl FnMut() -> u32) -> u128 {
        (u128::from(zuc()) << 96)
            | (u128::from(zuc()) << 64)
            | (u128::from(zuc()) << 32)
            | u128::from(zuc())
    }

    fn high(&self) -> u64 {
        (self >> 64) as u64
    }
    fn set_low(&mut self, low: Self::Word) {
        *self |= Self::from(low);
    }
}

// 128 bit word
impl MacWord for u128 {
    type KeyPair = U256;
    const D: [u8; 16] = [
        0b010_0011, 0b010_1111, 0b010_0101, 0b010_1010, 0b110_1101, 0b100_0000, 0b100_0000,
        0b100_0000, 0b100_0000, 0b100_0000, 0b100_0000, 0b100_0000, 0b100_0000, 0b101_0010,
        0b001_0000, 0b011_0000,
    ];
    const HIGH_BIT: u128 = 1 << (std::mem::size_of::<Self>() * 8 - 1);
    fn gen_word(zuc: &mut impl FnMut() -> u32) -> u128 {
        (u128::from(zuc()) << 96)
            | (u128::from(zuc()) << 64)
            | (u128::from(zuc()) << 32)
            | u128::from(zuc())
    }
    fn from_chunk(chunk: &[u8]) -> u128 {
        u128::from_be_bytes(chunk[0..Self::BYTE_SIZE].try_into().expect("impossible"))
    }
}

impl MacKeyPair for U256 {
    type Word = u128;
    fn gen_key_pair(zuc: &mut impl FnMut() -> u32) -> U256 {
        let high = (u128::from(zuc()) << 96)
            | (u128::from(zuc()) << 64)
            | (u128::from(zuc()) << 32)
            | u128::from(zuc());
        let low = (u128::from(zuc()) << 96)
            | (u128::from(zuc()) << 64)
            | (u128::from(zuc()) << 32)
            | u128::from(zuc());
        U256::new(high, low)
    }

    fn high(&self) -> u128 {
        self.high
    }
    fn set_low(&mut self, low: Self::Word) {
        self.low = low;
    }
}

/// xor t for zuc 256 mac
#[inline(always)]
fn zuc_256_mac_xor_t<T>(bits: &mut T, key: &mut T::KeyPair, tag: &mut T)
where
    T: MacWord,
{
    let k: T = if bits.test_high_bit() {
        key.high()
    } else {
        T::from(0)
    };
    *tag ^= k;
    bits.shl_once();
    key.shl_once();
}

/// get remaining bits for zuc 256 mac
fn zuc256_mac_get_remaining_bits<T>(bitlen: usize, m: &[u8]) -> T
where
    T: MacWord,
{
    let i = bitlen / T::BIT_SIZE * T::BYTE_SIZE;
    let j = (bitlen % T::BIT_SIZE - 1) / 8;
    let mut bytes = vec![0u8; T::BYTE_SIZE];
    bytes[..=j].copy_from_slice(&m[i..=i + j]);
    T::from_chunk(&bytes)
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
    let mut zuc = Zuc256Core::new_with_d(ik, iv, &T::D);
    let mut tag: T = T::gen_word(&mut || zuc.generate());
    let mut key: T::KeyPair = T::KeyPair::gen_key_pair(&mut || zuc.generate());

    for chunk in m[..(bitlen / 8)].chunks_exact(T::BYTE_SIZE) {
        let mut bits = T::from_chunk(chunk);

        for _ in 0..T::BIT_SIZE {
            zuc_256_mac_xor_t(&mut bits, &mut key, &mut tag);
        }

        key.set_low(T::gen_word(&mut || zuc.generate()));
    }

    if bitlen % T::BIT_SIZE == 0 {
        tag ^= key.high();
    } else {
        let mut bits = zuc256_mac_get_remaining_bits::<T>(bitlen, m);

        for _ in 0..(bitlen % T::BIT_SIZE) {
            zuc_256_mac_xor_t(&mut bits, &mut key, &mut tag);
        }

        tag ^= key.high();
    }

    tag
}

#[cfg(test)]
mod tests {
    use crate::zuc256_generate_mac;

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
        expected_32: 0x5c7_c8b88,
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
            println!("1");
            assert_eq!(mac_32, x.expected_32);

            let mac_64 = zuc256_generate_mac::<u64>(&x.k, &x.iv, x.length, x.m);
            println!("2");
            assert_eq!(mac_64, x.expected_64);

            let mac_128 = zuc256_generate_mac::<u128>(&x.k, &x.iv, x.length, x.m);
            println!("3");
            assert_eq!(mac_128, x.expected_128);
        }
    }
}
