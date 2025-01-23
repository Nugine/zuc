use super::keystream::Keystream;
use super::u256::U256;

use core::fmt;
use core::mem::size_of;
use core::ops::{BitXorAssign, ShlAssign};

use cipher::generic_array::typenum;
use cipher::generic_array::ArrayLength;
use cipher::generic_array::GenericArray;
use numeric_cast::TruncatingCast;

/// Mac Word
pub trait MacWord
where
    Self: Sized + Copy + Eq,
    Self: fmt::Debug + fmt::LowerHex + fmt::UpperHex,
    Self: BitXorAssign + ShlAssign<usize>,
{
    /// Mac Key Pair Type
    type KeyPair: MacKeyPair<Word = Self>;

    type ByteSize: ArrayLength<u8>;

    /// generate word
    fn gen_word(zuc: &mut impl Keystream<Word = u32>) -> Self;

    /// convert key from big endian bytes
    fn from_be_slice(chunk: &[u8]) -> Self;

    /// convert key to big endian bytes
    fn to_be_array(self) -> GenericArray<u8, Self::ByteSize>;

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
    fn gen_key_pair(zuc: &mut impl Keystream<Word = u32>) -> Self;

    /// get high bits
    fn high(&self) -> Self::Word;

    /// set low bits
    fn set_low(&mut self, low: Self::Word);
}

// 32 bit word
impl MacWord for u32 {
    type KeyPair = u64;

    type ByteSize = typenum::U4;

    #[inline(always)]
    fn gen_word(zuc: &mut impl Keystream<Word = u32>) -> u32 {
        zuc.next_key()
    }

    #[inline(always)]
    fn from_be_slice(chunk: &[u8]) -> u32 {
        match chunk.try_into() {
            Ok(arr) => u32::from_be_bytes(arr),
            Err(_) => unreachable!(),
        }
    }

    #[inline(always)]
    fn to_be_array(self) -> GenericArray<u8, Self::ByteSize> {
        GenericArray::from(self.to_be_bytes())
    }

    #[inline(always)]
    fn test_high_bit(&self) -> bool {
        let high_bit: u32 = 1 << (32 - 1);
        (*self & high_bit) != 0
    }
}

// key pair form 32 bit word
impl MacKeyPair for u64 {
    type Word = u32;

    #[inline(always)]
    fn gen_key_pair(zuc: &mut impl Keystream<Word = u32>) -> u64 {
        u64::gen_word(zuc)
    }

    #[inline(always)]
    fn high(&self) -> u32 {
        (self >> 32) as u32
    }

    #[inline(always)]
    fn set_low(&mut self, low: Self::Word) {
        *self |= Self::from(low);
    }
}

// 64 bit word
impl MacWord for u64 {
    type KeyPair = u128;

    type ByteSize = typenum::U8;

    #[inline(always)]
    fn gen_word(zuc: &mut impl Keystream<Word = u32>) -> u64 {
        (u64::from(zuc.next_key()) << 32) | u64::from(zuc.next_key())
    }

    #[inline(always)]
    fn from_be_slice(chunk: &[u8]) -> u64 {
        match chunk.try_into() {
            Ok(arr) => u64::from_be_bytes(arr),
            Err(_) => unreachable!(),
        }
    }

    #[inline(always)]
    fn to_be_array(self) -> GenericArray<u8, Self::ByteSize> {
        GenericArray::from(self.to_be_bytes())
    }

    #[inline(always)]
    fn test_high_bit(&self) -> bool {
        let high_bit: u64 = 1 << (64 - 1);
        (*self & high_bit) != 0
    }
}

// key pair form 64 bit word
impl MacKeyPair for u128 {
    type Word = u64;

    #[inline(always)]
    fn gen_key_pair(zuc: &mut impl Keystream<Word = u32>) -> u128 {
        u128::gen_word(zuc)
    }

    #[inline(always)]
    fn high(&self) -> u64 {
        (self >> 64) as u64
    }

    #[inline(always)]
    fn set_low(&mut self, low: Self::Word) {
        *self |= Self::from(low);
    }
}

// 128 bit word
impl MacWord for u128 {
    type KeyPair = U256;

    type ByteSize = typenum::U16;

    #[inline(always)]
    fn gen_word(zuc: &mut impl Keystream<Word = u32>) -> u128 {
        let a = (
            u128::from(zuc.next_key()) << 96,
            u128::from(zuc.next_key()) << 64,
            u128::from(zuc.next_key()) << 32,
            u128::from(zuc.next_key()),
        );
        a.0 | a.1 | a.2 | a.3
    }

    #[inline(always)]
    fn from_be_slice(chunk: &[u8]) -> u128 {
        match chunk.try_into() {
            Ok(arr) => u128::from_be_bytes(arr),
            Err(_) => unreachable!(),
        }
    }

    #[inline(always)]
    fn to_be_array(self) -> GenericArray<u8, Self::ByteSize> {
        GenericArray::from(self.to_be_bytes())
    }

    #[inline(always)]
    fn test_high_bit(&self) -> bool {
        let high_bit: u128 = 1 << (128 - 1);
        (*self & high_bit) != 0
    }
}

// key pair form 128 bit word
impl MacKeyPair for U256 {
    type Word = u128;

    fn gen_key_pair(zuc: &mut impl Keystream<Word = u32>) -> U256 {
        let high = u128::gen_word(zuc);
        let low = u128::gen_word(zuc);
        U256::new(high, low)
    }

    fn high(&self) -> u128 {
        self.high
    }

    fn set_low(&mut self, low: Self::Word) {
        self.low = low;
    }
}

#[inline(always)]
fn copy(dst: &mut [u8], src: &[u8]) {
    dst[..src.len()].copy_from_slice(src);
}

pub struct MacCore<S, T>
where
    S: Keystream,
    T: MacWord,
{
    pub zuc: S,
    pub key: T::KeyPair,
    pub tag: T,

    pub rem: GenericArray<u8, T::ByteSize>,
    pub cnt: u8,
}

impl<S, T> MacCore<S, T>
where
    S: Keystream<Word = u32>,
    T: MacWord,
{
    #[inline(always)]
    fn xor_step(bits: &mut T, tag: &mut T, key: &mut T::KeyPair) {
        if bits.test_high_bit() {
            *tag ^= key.high();
        }
        *bits <<= 1;
        *key <<= 1;
    }

    #[inline(always)]
    fn feed_word(mut bits: T, tag: &mut T, key: &mut T::KeyPair, zuc: &mut S) {
        for _ in 0..size_of::<T>() * 8 {
            Self::xor_step(&mut bits, tag, key);
        }
        key.set_low(T::gen_word(zuc));
    }

    pub fn update(&mut self, mut msg: &[u8]) {
        if msg.is_empty() {
            return;
        }

        let zuc = &mut self.zuc;
        let mut key = self.key;
        let mut tag = self.tag;
        let rem = self.rem.as_mut_slice();
        let cnt = self.cnt as usize;

        if cnt > 0 {
            if cnt + msg.len() < size_of::<T>() {
                copy(&mut rem[cnt..], msg);
                self.cnt += msg.len().truncating_cast::<u8>();
                return;
            }

            let (head, tail) = msg.split_at(size_of::<T>() - cnt);
            copy(&mut rem[cnt..], head);
            msg = tail;

            let bits = T::from_be_slice(rem);
            Self::feed_word(bits, &mut tag, &mut key, zuc);
        }

        let mut chunks = msg.chunks_exact(size_of::<T>());
        for chunk in &mut chunks {
            let bits = T::from_be_slice(chunk);
            Self::feed_word(bits, &mut tag, &mut key, zuc);
        }

        {
            let rest = chunks.remainder();
            copy(rem, rest);
            self.cnt = rest.len().truncating_cast::<u8>();
        }

        self.key = key;
        self.tag = tag;
    }

    #[must_use]
    pub fn finish(&mut self, mut tail: &[u8], mut bitlen: usize) -> usize {
        assert!(bitlen <= tail.len() * 8);

        if bitlen >= 8 {
            self.update(&tail[..(bitlen / 8)]);
            tail = &tail[(bitlen / 8)..];
            bitlen %= 8;
        }

        let mut key = self.key;
        let mut tag = self.tag;
        let rem = self.rem.as_mut_slice();
        let cnt = self.cnt as usize;

        if bitlen != 0 {
            rem[cnt] = tail[0];
        }

        let bitlen = cnt * 8 + bitlen;
        if bitlen != 0 {
            let mut bits = T::from_be_slice(rem);
            for _ in 0..bitlen {
                Self::xor_step(&mut bits, &mut tag, &mut key);
            }

            self.tag = tag;
            self.key = key;
        }

        bitlen
    }
}
