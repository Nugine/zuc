use crate::internal::mac::MacCore;
use crate::zuc128::keystream::Zuc128Keystream;

const BLOCK_SIZE: usize = 16;

pub(super) fn update(core: &mut MacCore<Zuc128Keystream, u32>, mut msg: &[u8]) -> bool {
    if !backend::is_supported() {
        return false;
    }

    if msg.is_empty() {
        return true;
    }

    if core.cnt != 0 {
        let cnt = usize::from(core.cnt);
        let n = (size_of::<u32>() - cnt).min(msg.len());
        core.update(&msg[..n]);
        msg = &msg[n..];

        if core.cnt != 0 {
            return true;
        }
    }

    let n = msg.len() / BLOCK_SIZE * BLOCK_SIZE;
    if n != 0 {
        let (blocks, rest) = msg.split_at(n);
        backend::process_blocks(&mut core.tag, &mut core.key, &mut core.zuc, blocks);
        msg = rest;
    }

    if !msg.is_empty() {
        core.update(msg);
    }

    true
}

#[cfg(target_arch = "x86_64")]
mod backend {
    use super::BLOCK_SIZE;
    use crate::zuc128::keystream::Zuc128Keystream;
    use core::arch::x86_64::{__m128i, _mm_clmulepi64_si128, _mm_cvtsi128_si64, _mm_set_epi64x};
    use numeric_cast::TruncatingCast;

    pub(super) fn is_supported() -> bool {
        #[cfg(feature = "std")]
        {
            std::is_x86_feature_detected!("pclmulqdq")
        }

        #[cfg(not(feature = "std"))]
        {
            cfg!(target_feature = "pclmulqdq")
        }
    }

    pub(super) fn process_blocks(
        tag: &mut u32,
        key: &mut u64,
        zuc: &mut Zuc128Keystream,
        blocks: &[u8],
    ) {
        debug_assert_eq!(blocks.len() % BLOCK_SIZE, 0);

        // SAFETY: `is_supported` checks PCLMULQDQ at run time with `std` and at
        // compile time without `std`.
        unsafe {
            process_blocks_inner(tag, key, zuc, blocks);
        }
    }

    #[target_feature(enable = "pclmulqdq")]
    #[target_feature(enable = "sse2")]
    unsafe fn process_blocks_inner(
        tag: &mut u32,
        key: &mut u64,
        zuc: &mut Zuc128Keystream,
        blocks: &[u8],
    ) {
        for block in blocks.chunks_exact(BLOCK_SIZE) {
            let k0 = (*key >> 32).truncating_cast::<u32>();
            let k1 = (*key).truncating_cast::<u32>();
            let k2 = zuc.generate();
            let k3 = zuc.generate();
            let k4 = zuc.generate();
            let k5 = zuc.generate();

            let m0 = u32::from_be_bytes([block[0], block[1], block[2], block[3]]).reverse_bits();
            let m1 = u32::from_be_bytes([block[4], block[5], block[6], block[7]]).reverse_bits();
            let m2 = u32::from_be_bytes([block[8], block[9], block[10], block[11]]).reverse_bits();
            let m3 =
                u32::from_be_bytes([block[12], block[13], block[14], block[15]]).reverse_bits();

            let d01 = _mm_set_epi64x(i64::from(m1), i64::from(m0));
            let d23 = _mm_set_epi64x(i64::from(m3), i64::from(m2));
            let k01 = _mm_set_epi64x(key_pair(k1, k2), key_pair(k0, k1));
            let k23 = _mm_set_epi64x(key_pair(k3, k4), key_pair(k2, k3));

            let p0 = _mm_clmulepi64_si128::<0x00>(d01, k01);
            let p1 = _mm_clmulepi64_si128::<0x11>(d01, k01);
            let p2 = _mm_clmulepi64_si128::<0x00>(d23, k23);
            let p3 = _mm_clmulepi64_si128::<0x11>(d23, k23);

            *tag ^= contribution(p0) ^ contribution(p1) ^ contribution(p2) ^ contribution(p3);
            *key = (u64::from(k4) << 32) | u64::from(k5);
        }
    }

    #[target_feature(enable = "sse2")]
    unsafe fn contribution(product: __m128i) -> u32 {
        let low = u64::from_ne_bytes(_mm_cvtsi128_si64(product).to_ne_bytes());
        (low >> 32).truncating_cast::<u32>()
    }

    #[inline(always)]
    fn key_pair(high: u32, low: u32) -> i64 {
        let pair = (u64::from(high) << 32) | u64::from(low);
        i64::from_ne_bytes(pair.to_ne_bytes())
    }
}

#[cfg(not(target_arch = "x86_64"))]
mod backend {
    use crate::zuc128::keystream::Zuc128Keystream;

    pub(super) fn is_supported() -> bool {
        false
    }

    pub(super) fn process_blocks(
        _tag: &mut u32,
        _key: &mut u64,
        _zuc: &mut Zuc128Keystream,
        _blocks: &[u8],
    ) {
        unreachable!();
    }
}
