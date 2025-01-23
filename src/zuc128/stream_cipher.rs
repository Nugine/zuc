use super::Zuc128Keystream;

use crate::internal::stream_cipher::xor_inplace;

/// ZUC128 stream cipher
/// ([GB/T 33133.1-2016](https://openstd.samr.gov.cn/bzgk/gb/newGbInfo?hcno=8C41A3AEECCA52B5C0011C8010CF0715))
pub type Zuc128StreamCipher = cipher::StreamCipherCoreWrapper<Zuc128Keystream>;

/// ZUC128 confidentiality algorithm
/// ([GB/T 33133.2-2021](https://openstd.samr.gov.cn/bzgk/gb/newGbInfo?hcno=5D3CBA3ADEC7989344BD1E63006EF2B3))
///
/// ## Input
/// | name   | size     | description                 |
/// | ------ | -------- | --------------------------- |
/// | ck     | 128 bits | confidentiality key         |
/// | iv     | 128 bits | initial vector              |
/// | data   | -        | the bitstream               |
/// | bitlen | -        | bit length of the bitstream |
pub fn zuc128_xor_inplace(ck: &[u8; 16], iv: &[u8; 16], data: &mut [u8], bitlen: usize) {
    let mut zuc = Zuc128Keystream::new(ck, iv);
    xor_inplace(&mut zuc, data, bitlen);
}
