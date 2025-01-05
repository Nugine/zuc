//! 256-bit unsigned integer

use std::ops::ShlAssign;

/// 256-bit unsigned integer
pub struct U256 {
    /// high 128 bits
    pub high: u128,
    /// low 128 bits
    pub low: u128,
}

impl U256 {
    /// Create a [`U256`] from two u128
    pub fn new(high: u128, low: u128) -> Self {
        U256 { high, low }
    }
}

impl ShlAssign<usize> for U256 {
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
