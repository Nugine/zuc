//! Utilities

use std::ops::ShlAssign;

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
/// BE Uint 256 simple implement for zuc256
pub struct Uint256 {
    /// high 128bit of be uint 256
    pub high: u128,
    /// low 128bit of be uint 256
    pub low: u128,
}

impl Uint256 {
    /// new uint256  for two u128
    pub fn new(high: u128, low: u128) -> Self {
        Uint256 { high, low }
    }
}
impl ShlAssign<usize> for Uint256 {
    fn shl_assign(&mut self, rhs: usize) {
        if rhs >= 256 {
            self.high = 0;
            self.low = 0;
        } else if rhs == 128 {
            self.high = self.low;
            self.low = 0;
        } else if rhs > 128 {
            self.high = self.low << (rhs - 128);
            self.low = 0;
        } else {
            let new_high = (self.high << rhs) | (self.low >> (128 - rhs));
            let new_low = self.low << rhs;
            self.high = new_high;
            self.low = new_low;
        }
    }
}
