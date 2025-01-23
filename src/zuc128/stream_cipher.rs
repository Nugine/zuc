use super::Zuc128Keystream;

use crate::internal::stream_cipher::xor_to_vec;

/// ZUC128 stream cipher
/// ([GB/T 33133.1-2016](https://openstd.samr.gov.cn/bzgk/gb/newGbInfo?hcno=8C41A3AEECCA52B5C0011C8010CF0715))
pub type Zuc128StreamCipher = cipher::StreamCipherCoreWrapper<Zuc128Keystream>;

/// ZUC128 xor encryption algorithm
/// ([GB/T 33133.2-2021](https://openstd.samr.gov.cn/bzgk/gb/newGbInfo?hcno=5D3CBA3ADEC7989344BD1E63006EF2B3))
///
/// Input:
/// - `ck`:       128bit  confidentiality key
/// - `iv`:       128bit  initial vector
/// - `length`:   32bit   bit length of plaintext information stream
/// - `ibs`:      input bitstream
///
/// Output:
/// - [`Vec<u8>`]:  encrypted bit stream
///
/// # Panics
/// + Panics if `length` is greater than the length of `ibs` times 8.
/// + Panics if `length` is greater than `usize::MAX`.
#[must_use]
pub fn zuc128_xor_encrypt(ck: &[u8; 16], iv: &[u8; 16], length: u32, ibs: &[u8]) -> Vec<u8> {
    let bitlen = usize::try_from(length).expect("bit length overflow");
    let mut zuc = Zuc128Keystream::new(ck, iv);
    xor_to_vec(&mut zuc, ibs, bitlen)
}
