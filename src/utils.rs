//! Utilities

/// (a + b) mod (2^32)
#[inline(always)]
pub fn add(a: u32, b: u32) -> u32 {
    a.wrapping_add(b)
}

/// rotate left
#[inline(always)]
pub fn rol(x: u32, n: u32) -> u32 {
    x.rotate_left(n)
}
