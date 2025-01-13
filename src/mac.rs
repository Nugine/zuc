//! private for sealed trait

use crate::u256::U256;

use std::ops::{BitXorAssign, ShlAssign};

/// Mac Word
pub trait MacWord
where
    Self: Sized + Copy,
    Self: BitXorAssign,
    Self: ShlAssign<usize>,
{
    /// Mac Key Pair Type
    type KeyPair: MacKeyPair<Word = Self>;

    /// generate word
    fn gen_word(zuc: &mut impl FnMut() -> u32) -> Self;

    /// convert key from big endian bytes
    fn from_chunk(chunk: &[u8]) -> Self;

    /// test the highest bit of the word
    fn test_high_bit(&self) -> bool;
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
}

// 32 bit word
impl MacWord for u32 {
    type KeyPair = u64;

    fn gen_word(zuc: &mut impl FnMut() -> u32) -> u32 {
        zuc()
    }

    fn from_chunk(chunk: &[u8]) -> u32 {
        match chunk.try_into() {
            Ok(arr) => u32::from_be_bytes(arr),
            Err(_) => unreachable!(),
        }
    }

    fn test_high_bit(&self) -> bool {
        let high_bit: u32 = 1 << (32 - 1);
        (*self & high_bit) != 0
    }
}

// key pair form 32 bit word
impl MacKeyPair for u64 {
    type Word = u32;

    fn gen_key_pair(zuc: &mut impl FnMut() -> u32) -> u64 {
        u64::gen_word(zuc)
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

    fn gen_word(zuc: &mut impl FnMut() -> u32) -> u64 {
        (u64::from(zuc()) << 32) | u64::from(zuc())
    }

    fn from_chunk(chunk: &[u8]) -> u64 {
        match chunk.try_into() {
            Ok(arr) => u64::from_be_bytes(arr),
            Err(_) => unreachable!(),
        }
    }

    fn test_high_bit(&self) -> bool {
        let high_bit: u64 = 1 << (64 - 1);
        (*self & high_bit) != 0
    }
}

// key pair form 64 bit word
impl MacKeyPair for u128 {
    type Word = u64;

    fn gen_key_pair(zuc: &mut impl FnMut() -> u32) -> u128 {
        u128::gen_word(zuc)
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

    fn gen_word(zuc: &mut impl FnMut() -> u32) -> u128 {
        (u128::from(zuc()) << 96)
            | (u128::from(zuc()) << 64)
            | (u128::from(zuc()) << 32)
            | u128::from(zuc())
    }

    fn from_chunk(chunk: &[u8]) -> u128 {
        match chunk.try_into() {
            Ok(arr) => u128::from_be_bytes(arr),
            Err(_) => unreachable!(),
        }
    }

    fn test_high_bit(&self) -> bool {
        let high_bit: u128 = 1 << (128 - 1);
        (*self & high_bit) != 0
    }
}

// key pair form 128 bit word
impl MacKeyPair for U256 {
    type Word = u128;

    fn gen_key_pair(zuc: &mut impl FnMut() -> u32) -> U256 {
        let high = u128::gen_word(&mut || zuc());
        let low = u128::gen_word(&mut || zuc());
        U256::new(high, low)
    }

    fn high(&self) -> u128 {
        self.high
    }

    fn set_low(&mut self, low: Self::Word) {
        self.low = low;
    }
}
