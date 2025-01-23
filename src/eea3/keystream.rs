use crate::internal::keystream::Keystream;
use crate::zuc128::Zuc128Keystream;

/// 128-EEA3 keystream generator
/// ([EEA3-EIA3-specification](https://www.gsma.com/solutions-and-impact/technologies/security/wp-content/uploads/2019/05/EEA3_EIA3_specification_v1_8.pdf))
pub struct Eea3Keystream(Zuc128Keystream);

impl Eea3Keystream {
    /// Creates a 128-EEA3 keystream generator
    #[must_use]
    pub fn new(count: u32, bearer: u8, direction: u8, ck: &[u8; 16]) -> Self {
        let bearer = bearer & 0x1f;
        let direction = direction & 0x01;
        let count = count.to_be_bytes();

        let mut iv = [0_u8; 16];
        iv[0] = count[0];
        iv[1] = count[1];
        iv[2] = count[2];
        iv[3] = count[3];
        iv[4] = (bearer << 3) | (direction << 2);

        iv[8] = iv[0];
        iv[9] = iv[1];
        iv[10] = iv[2];
        iv[11] = iv[3];
        iv[12] = iv[4];

        Self(Zuc128Keystream::new(ck, &iv))
    }

    ///  Generates the next 32-bit word in 128-EEA3 keystream
    pub fn generate(&mut self) -> u32 {
        self.0.generate()
    }
}

impl Keystream for Eea3Keystream {
    type Word = u32;

    fn next_key(&mut self) -> Self::Word {
        self.generate()
    }
}

impl Iterator for Eea3Keystream {
    type Item = u32;

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        Some(self.generate())
    }
}

impl cipher::AlgorithmName for Eea3Keystream {
    fn write_alg_name(f: &mut core::fmt::Formatter) -> core::fmt::Result {
        write!(f, "Eea3")
    }
}

impl cipher::KeySizeUser for Eea3Keystream {
    type KeySize = cipher::typenum::U16;
}

impl cipher::IvSizeUser for Eea3Keystream {
    type IvSize = cipher::typenum::U16;
}

impl cipher::BlockSizeUser for Eea3Keystream {
    type BlockSize = cipher::typenum::U4;
}

impl cipher::ParBlocksSizeUser for Eea3Keystream {
    type ParBlocksSize = cipher::typenum::U1;
}

impl cipher::StreamBackend for Eea3Keystream {
    fn gen_ks_block(&mut self, block: &mut cipher::Block<Self>) {
        let z = self.generate();
        block.copy_from_slice(&z.to_be_bytes());
    }
}

impl cipher::StreamCipherCore for Eea3Keystream {
    fn remaining_blocks(&self) -> Option<usize> {
        None
    }

    fn process_with_backend(&mut self, f: impl cipher::StreamClosure<BlockSize = Self::BlockSize>) {
        f.call(self);
    }
}
