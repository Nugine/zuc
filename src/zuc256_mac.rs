//! ZUC-256 Algorithms MAC generate
use crate::u256::U256;
use crate::zuc256::Zuc256Core;
use std::ops::{BitAnd, BitXorAssign, ShlAssign, ShrAssign};

mod private {
    //! private for sealed trait
    use crate::u256::U256;

    /// Sealed trait
    pub trait Sealed {}
    impl Sealed for u32 {}
    impl Sealed for u64 {}
    impl Sealed for u128 {}
    impl Sealed for U256 {}
}

/// trait for mac type (u32, u64, u128)
pub trait Zuc256MACType<T>: Sized + private::Sealed
where
    T: BitXorAssign<T>
        + BitAnd<Output = T>
        + ShlAssign<usize>
        + ShrAssign<usize>
        + Eq
        + From<u8>
        + Copy,
{
    /// d constants
    const D: [u8; 16];

    /// bit size of T
    const BIT_SIZE: usize = std::mem::size_of::<Self>() * 8;

    /// byte size of T
    const BYTE_SIZE: usize = std::mem::size_of::<Self>();

    /// high bit 1000...000
    const HIGH_BIT: T;

    /// get T bits from message chunk
    fn from_chunk(chunk: &[u8]) -> T;

    /// generate zuc T word
    fn generate_word(zuc: &mut Zuc256Core) -> T;

    /// get remaining bits for zuc from message
    fn get_remaining_bits(bitlen: usize, m: &[u8]) -> T;

    /// xor t for zuc mac
    #[inline(always)]
    fn xor_t(bits: &mut T, key: &mut Self::KeyType, tag: &mut T) {
        let k: T = if *bits & Self::HIGH_BIT == T::from(0) {
            T::from(0)
        } else {
            key.high()
        };
        *tag ^= k;
        *bits <<= 1;
        *key <<= 1;
    }

    /// key type
    type KeyType: ShlAssign<usize> + Zuc256MACKeyTransform<Half = T>;
}

impl Zuc256MACType<u32> for u32 {
    type KeyType = u64;
    const D: [u8; 16] = [
        0b010_0010, 0b010_1111, 0b010_0101, 0b010_1010, 0b110_1101, 0b100_0000, 0b100_0000,
        0b100_0000, 0b100_0000, 0b100_0000, 0b100_0000, 0b100_0000, 0b100_0000, 0b101_0010,
        0b001_0000, 0b011_0000,
    ];
    const HIGH_BIT: u32 = 0x8000_0000;
    fn from_chunk(chunk: &[u8]) -> u32 {
        u32::from_be_bytes(chunk[0..u32::BYTE_SIZE].try_into().expect("impossible"))
    }
    fn generate_word(zuc: &mut Zuc256Core) -> u32 {
        zuc.generate()
    }
    fn get_remaining_bits(bitlen: usize, m: &[u8]) -> u32 {
        let i = bitlen / u32::BIT_SIZE * u32::BYTE_SIZE;
        let j = (bitlen % u32::BIT_SIZE - 1) / 8;
        let mut bytes = [0u8; 4];
        bytes[..=j].copy_from_slice(&m[i..=i + j]);
        u32::from_be_bytes(bytes)
    }
}

impl Zuc256MACType<u64> for u64 {
    type KeyType = u128;
    const D: [u8; 16] = [
        0b010_0011, 0b010_1111, 0b010_0100, 0b010_1010, 0b110_1101, 0b100_0000, 0b100_0000,
        0b100_0000, 0b100_0000, 0b100_0000, 0b100_0000, 0b100_0000, 0b100_0000, 0b101_0010,
        0b001_0000, 0b011_0000,
    ];
    const HIGH_BIT: u64 = 0x8000_0000_0000_0000;
    fn generate_word(zuc: &mut Zuc256Core) -> u64 {
        (u64::from(zuc.generate()) << 32) | u64::from(zuc.generate())
    }
    fn from_chunk(chunk: &[u8]) -> u64 {
        u64::from_be_bytes(chunk[0..u64::BYTE_SIZE].try_into().expect("impossible"))
    }
    fn get_remaining_bits(bitlen: usize, m: &[u8]) -> u64 {
        let i = bitlen / u64::BIT_SIZE * u64::BYTE_SIZE;
        let j = (bitlen % u64::BIT_SIZE - 1) / 8;
        let mut bytes = [0u8; 8];
        bytes[..=j].copy_from_slice(&m[i..=i + j]);
        Self::from_be_bytes(bytes)
    }
}

impl Zuc256MACType<u128> for u128 {
    type KeyType = U256;
    const D: [u8; 16] = [
        0b010_0011, 0b010_1111, 0b010_0101, 0b010_1010, 0b110_1101, 0b100_0000, 0b100_0000,
        0b100_0000, 0b100_0000, 0b100_0000, 0b100_0000, 0b100_0000, 0b100_0000, 0b101_0010,
        0b001_0000, 0b011_0000,
    ];
    const HIGH_BIT: u128 = 0x8000_0000_0000_0000_0000_0000_0000_0000;
    fn generate_word(zuc: &mut Zuc256Core) -> u128 {
        (u128::from(zuc.generate()) << 96)
            | (u128::from(zuc.generate()) << 64)
            | (u128::from(zuc.generate()) << 32)
            | u128::from(zuc.generate())
    }
    fn from_chunk(chunk: &[u8]) -> u128 {
        u128::from_be_bytes(chunk[0..u128::BYTE_SIZE].try_into().expect("impossible"))
    }

    fn get_remaining_bits(bitlen: usize, m: &[u8]) -> u128 {
        let i = bitlen / u128::BIT_SIZE * u128::BYTE_SIZE;
        let j = (bitlen % u128::BIT_SIZE - 1) / 8;
        let mut bytes = [0u8; 16];
        bytes[..=j].copy_from_slice(&m[i..=i + j]);
        Self::from_be_bytes(bytes)
    }
}

/// trait for zuc 256 mac key transform
pub trait Zuc256MACKeyTransform: private::Sealed {
    /// half of Key (T)
    type Half;
    /// high word from zuc 256 key
    fn high(&self) -> Self::Half;

    /// low word from zuc 256 key
    // TODO: zuc 128 and keystream genrator could use it
    #[allow(unused)]
    fn low(&self) -> Self::Half;

    /// new zuc 256 key form 2 word
    fn new(high: Self::Half, low: Self::Half) -> Self;

    /// set low word
    fn set_low(&mut self, low: Self::Half);
}

#[allow(clippy::cast_possible_truncation)]
impl Zuc256MACKeyTransform for u64 {
    type Half = u32;
    fn high(&self) -> u32 {
        (self >> 32) as u32
    }
    fn low(&self) -> u32 {
        *self as u32
    }
    fn new(high: u32, low: u32) -> u64 {
        (u64::from(high) << 32) | u64::from(low)
    }
    fn set_low(&mut self, low: u32) {
        *self ^= u64::from(low);
    }
}

#[allow(clippy::cast_possible_truncation)]
impl Zuc256MACKeyTransform for u128 {
    type Half = u64;
    fn high(&self) -> u64 {
        (self >> 64) as u64
    }
    fn low(&self) -> u64 {
        *self as u64
    }
    fn new(high: u64, low: u64) -> u128 {
        (u128::from(high) << 64) | u128::from(low)
    }
    fn set_low(&mut self, low: u64) {
        *self ^= u128::from(low);
    }
}

impl Zuc256MACKeyTransform for U256 {
    type Half = u128;
    fn high(&self) -> u128 {
        self.high
    }
    fn low(&self) -> u128 {
        self.low
    }
    fn new(high: u128, low: u128) -> U256 {
        U256::new(high, low)
    }
    fn set_low(&mut self, low: u128) {
        self.low = low;
    }
}

/// ZUC generate MAC algorithm
///  Generates the 128-bit word MAC from ZUC256 keystream
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
    T: Zuc256MACType<T>
        + ShlAssign<usize>
        + ShrAssign<usize>
        + BitXorAssign<T>
        + BitXorAssign<T>
        + BitAnd<Output = T>
        + Eq
        + From<u8>
        + Copy,
{
    let bitlen = usize::try_from(length).expect("`length` is greater than `usize::MAX`");
    assert!(
        bitlen <= m.len() * 8,
        "`length` is greater than the length of `m`"
    );
    let mut zuc = Zuc256Core::new_with_d(ik, iv, &T::D);
    let mut tag: T = T::generate_word(&mut zuc);
    let mut key: T::KeyType =
        T::KeyType::new(T::generate_word(&mut zuc), T::generate_word(&mut zuc));

    for chunk in m[..(bitlen / 8)].chunks_exact(T::BYTE_SIZE) {
        let mut bits = T::from_chunk(chunk);

        for _ in 0..T::BIT_SIZE {
            T::xor_t(&mut bits, &mut key, &mut tag);
        }

        key.set_low(T::generate_word(&mut zuc));
    }

    if bitlen % T::BIT_SIZE == 0 {
        tag ^= key.high();
    } else {
        let mut bits = T::get_remaining_bits(bitlen, m);

        for _ in 0..(bitlen % T::BIT_SIZE) {
            T::xor_t(&mut bits, &mut key, &mut tag);
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
        for ExampleMAC {
            k,
            iv,
            length,
            m,
            expected_32,
            expected_64,
            expected_128,
        } in [
            &EXAMPLE_MAC_2,
            &EXAMPLE_MAC_3,
            &EXAMPLE_MAC_4,
            &EXAMPLE_MAC_1,
        ] {
            let mac_32 = zuc256_generate_mac::<u32>(k, iv, *length, m);
            assert_eq!(mac_32, *expected_32);
            let mac_64 = zuc256_generate_mac::<u64>(k, iv, *length, m);
            assert_eq!(mac_64, *expected_64);
            let mac_128 = zuc256_generate_mac::<u128>(k, iv, *length, m);
            assert_eq!(mac_128, *expected_128);
        }
    }
}
