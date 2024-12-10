// src/zuc.rs
use super::utils::{add, add_m31, l1, l2, mul_m31};
use super::zuc_data::{S0, S1};
use std::mem;

/// S box transform
#[inline(always)]
fn sbox(x: u32) -> u32 {
    let x = x.to_be_bytes();
    let y = [
        S0[x[0] as usize],
        S1[x[1] as usize],
        S0[x[2] as usize],
        S1[x[3] as usize],
    ];
    u32::from_be_bytes(y)
}
/// ZUC keystream generator
#[derive(Clone, Debug)]
pub struct ZUC {
    /// LFSR registers (31-bit words x16)
    pub(crate) s: [u32; 16],

    /// R1 state unit (32 bits)
    pub(crate) r1: u32,

    /// R2 state unit (32 bits)
    pub(crate) r2: u32,

    /// X buffer
    pub(crate) x: [u32; 4],
}

// 公共实现
impl ZUC {
    /// Zero-initialized
    #[allow(unsafe_code)]
    pub fn zeroed() -> Self {
        unsafe { mem::zeroed() }
    }

    /// Creates a ZUC128 keystream generator
    pub fn init(&mut self, s: [u32; 16]) {
        self.s = s;
        for _ in 0..32 {
            self.bit_reconstruction();
            let w = self.f();
            self.lfsr_with_initialization_mode(w >> 1);
        }
        self.generate();
    }
    /// `BitReconstruction` function
    fn bit_reconstruction(&mut self) {
        let Self { s, x, .. } = self;
        x[0] = ((s[15] & 0x7FFF_8000) << 1) | (s[14] & 0xFFFF);
        x[1] = ((s[11] & 0xFFFF) << 16) | (s[9] >> 15);
        x[2] = ((s[7] & 0xFFFF) << 16) | (s[5] >> 15);
        x[3] = ((s[2] & 0xFFFF) << 16) | (s[0] >> 15);
    }

    /// F non-linear function
    fn f(&mut self) -> u32 {
        let Self { x, r1, r2, .. } = self;

        let w = add(x[0] ^ (*r1), *r2);
        let w1 = add(*r1, x[1]);
        let w2 = (*r2) ^ x[2];
        *r1 = sbox(l1((w1 << 16) | (w2 >> 16)));
        *r2 = sbox(l2((w2 << 16) | (w1 >> 16)));

        w
    }

    /// `LFSRWithInitialisationMode` function
    fn lfsr_with_initialization_mode(&mut self, u: u32) {
        let Self { s, .. } = self;
        let v = {
            let v1 = mul_m31(1 << 15, s[15]);
            let v2 = mul_m31(1 << 17, s[13]);
            let v3 = mul_m31(1 << 21, s[10]);
            let v4 = mul_m31(1 << 20, s[4]);
            let v5 = mul_m31((1 << 8) + 1, s[0]);
            add_m31(v1, add_m31(v2, add_m31(v3, add_m31(v4, v5))))
        };
        let mut s16 = add_m31(v, u);
        if s16 == 0 {
            s16 = (1 << 31) - 1;
        }
        for i in 0..15 {
            s[i] = s[i + 1];
        }
        s[15] = s16;
    }

    /// `LFSRWithWorkMode` function
    fn lfsr_with_work_mode(&mut self) {
        let Self { s, .. } = self;
        let v = {
            let v1 = mul_m31(1 << 15, s[15]);
            let v2 = mul_m31(1 << 17, s[13]);
            let v3 = mul_m31(1 << 21, s[10]);
            let v4 = mul_m31(1 << 20, s[4]);
            let v5 = mul_m31((1 << 8) + 1, s[0]);
            add_m31(v1, add_m31(v2, add_m31(v3, add_m31(v4, v5))))
        };
        let mut s16 = v;
        if s16 == 0 {
            s16 = (1 << 31) - 1;
        }
        for i in 0..15 {
            s[i] = s[i + 1];
        }
        s[15] = s16;
    }

    /// Generates the next 32-bit word in ZUC128 keystream
    pub fn generate(&mut self) -> u32 {
        self.bit_reconstruction();
        let z = self.f() ^ self.x[3];
        self.lfsr_with_work_mode();
        z
    }
}
