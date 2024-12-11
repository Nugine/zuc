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

/// (a * b) mod (2^31 - 1)
#[inline(always)]
pub fn mul_m31(a: u32, b: u32) -> u32 {
    ((u64::from(a) * u64::from(b)) % ((1 << 31) - 1)) as u32
}

/// (a + b) mod (2^31 - 1)
#[inline(always)]
pub fn add_m31(a: u32, b: u32) -> u32 {
    let c = add(a, b);
    (c & 0x7FFF_FFFF) + (c >> 31)
}
