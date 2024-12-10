//! ZUC-256 Algorithms

use crate::zuc_data::D_256;

use super::zuc::ZUC;
use super::zuc_data::{MAC_256_128, MAC_256_32, MAC_256_64};
/// mac length
pub enum MacLength {
    /// 32位mac
    Bit32,
    /// 64位mac
    Bit64,
    /// 128位mac
    Bit128,
}
/// concat u8 bits to 31bit u32
fn concat_bits(parts: &[u8]) -> u32 {
    let mut result: u32 = 0;
    for (i, &part) in parts.iter().enumerate() {
        let width = if i == 1 { 7 } else { 8 }; // 判断是 7 位 (D) 还是 8 位 (K/IV)
        result = (result << width) | part as u32;
    }
    result & 0x7FFFFFFF // 确保结果为 31 位
}

/// ZUC256 keystream generator
#[derive(Debug, Clone)]
pub struct ZUC256 {
    zuc: ZUC,
}

impl ZUC256 {
    /// Creates a ZUC256 keystream generator
    #[must_use]
    pub fn new(k: &[u8; 32], iv: &[u8; 25]) -> Self {
        let mut zuc = ZUC::zeroed();
        let mut s: [u32; 16] = [0; 16];
        let d = D_256;
        s[0] = concat_bits(&[k[0], d[0], k[21], k[16]]);
        s[1] = concat_bits(&[k[1], d[1], k[22], k[17]]);
        s[2] = concat_bits(&[k[2], d[2], k[23], k[18]]);
        s[3] = concat_bits(&[k[3], d[3], k[24], k[19]]);
        s[4] = concat_bits(&[k[4], d[4], k[25], k[20]]);
        s[5] = concat_bits(&[iv[0], (d[5] | iv[17]), k[5], k[26]]);
        s[6] = concat_bits(&[iv[1], (d[6] | iv[18]), k[6], k[27]]);
        s[7] = concat_bits(&[iv[10], (d[7] | iv[19]), k[7], iv[2]]);
        s[8] = concat_bits(&[k[8], (d[8] | iv[20]), iv[3], iv[11]]);
        s[9] = concat_bits(&[k[9], (d[9] | iv[21]), iv[12], iv[4]]);
        s[10] = concat_bits(&[iv[5], (d[10] | iv[22]), k[10], k[28]]);
        s[11] = concat_bits(&[k[11], (d[11] | iv[23]), iv[6], iv[13]]);
        s[12] = concat_bits(&[k[12], (d[12] | iv[24]), iv[7], iv[14]]);
        s[13] = concat_bits(&[k[13], d[13], iv[15], iv[8]]);
        s[14] = concat_bits(&[k[14], (d[14] | (k[31] >> 4)), iv[16], iv[9]]);
        s[15] = concat_bits(&[k[15], (d[15] | (k[31] & 0b_1111)), k[30], k[29]]);
        zuc.init(s);
        Self { zuc }
    }
    ///  Generates the next 32-bit word in ZUC256 keystream
    pub fn generate(&mut self) -> u32 {
        self.zuc.generate()
    }
    ///  Generates MAC
    pub fn generate_mac(&mut self, mac_length: MacLength) {
        todo!();
        let mac = match mac_length {
            MacLength::Bit32 => MAC_256_32,
            MacLength::Bit64 => MAC_256_64,
            MacLength::Bit128 => MAC_256_128,
        };
    }
}

impl Iterator for ZUC256 {
    type Item = u32;

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        Some(self.generate())
    }
}
