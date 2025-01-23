use super::keystream::Keystream;

use stdx::slice::SliceExt as _;

pub fn xor_inplace(zuc: &mut impl Keystream<Word = u32>, data: &mut [u8], bitlen: usize) {
    assert!(bitlen <= data.len() * 8);

    for chunk in data.as_chunks_mut_::<4>().0 {
        let k = zuc.next_key().to_be_bytes();
        for i in 0..4 {
            chunk[i] ^= k[i];
        }
    }

    {
        let i = data.len() / 4 * 4;
        let k = zuc.next_key().to_be_bytes();
        for j in 0..data.len() % 4 {
            data[i + j] ^= k[j];
        }
    }

    if bitlen % 8 != 0 {
        data[bitlen / 8] &= 0xFF << (8 - bitlen % 8);
    }

    for i in bitlen / 8 + 1..data.len() {
        data[i] = 0;
    }
}
