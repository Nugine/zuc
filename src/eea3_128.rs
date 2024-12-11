//! ZUC Confidentiality Algorithm
//! ([GB/T 33133.1-2016](https://openstd.samr.gov.cn/bzgk/gb/newGbInfo?hcno=5D3CBA3ADEC7989344BD1E63006EF2B3 ))

use crate::ZUC128;

/// zuc xor encryption algorithm
/// ([GB/T 33133.1-2016](https://openstd.samr.gov.cn/bzgk/gb/newGbInfo?hcno=5D3CBA3ADEC7989344BD1E63006EF2B3 ))
///
/// # input:
/// - ck:       128bit  confidentiality key
/// - iv:       128bit  initial vector
/// - length:       32bit   bit length of plaintext information stream
/// - ibs:          &[u8]   input bitstream
///
/// # output:
/// - Vec<u8>:  encrypted bit stream
#[must_use]
#[allow(clippy::needless_range_loop)]
#[allow(clippy::cast_possible_truncation)]
pub fn encryption_xor(ck: u128, iv: u128, length: u32, ibs: &[u8]) -> Vec<u8> {
    let l = (length + 31) / 32;

    let ck = ck.to_be_bytes();
    let iv = iv.to_ne_bytes();

    let mut zuc = ZUC128::new(&ck, &iv);
    let mut keys = (0..l)
        .flat_map(|_| {
            let z = zuc.generate().to_be();
            [z as u8, (z >> 8) as u8, (z >> 16) as u8, (z >> 24) as u8]
        })
        .collect::<Vec<u8>>();

    if length % 8 != 0 {
        keys[length as usize / 8] &= 0xFF << (8 - length % 8);
    }
    for i in length as usize / 8 + 1..keys.len() {
        keys[i] = 0x0;
    }

    let mut res = ibs.to_vec();
    res.iter_mut().zip(keys.iter()).for_each(|(ib, k)| *ib ^= k);
    res
}

/// eea3-128 privacy algorithm (3GPP LTE)
/// ([GB/T 33133.1-2016](https://openstd.samr.gov.cn/bzgk/gb/newGbInfo?hcno=5D3CBA3ADEC7989344BD1E63006EF2B3 ))
///
/// # Input:
/// - count:        32bit   counter
/// - bearer:       8bit    carrier layer identification
/// - direction:    1bit    transmission direction identification
/// - ck:           128bit  confidentiality key
/// - length:       32bit   bit length of plaintext information stream
/// - ibs:          &[u8]   input bitstream
///
/// # output:
/// - Vec<u8>:  encrypted bit stream
#[must_use]
#[allow(clippy::cast_possible_truncation)]
pub fn eea3_128(
    count: u32,
    bearer: u32,
    direction: u32,
    ck: u128,
    length: u32,
    ibs: &[u8],
) -> Vec<u8> {
    // init
    let bearer = bearer as u8 & ((1 << 6) - 1);
    let direction = direction as u8 & 0x1;

    let mut iv = [0_u8; 16];
    iv[0] = (count >> 24) as u8;
    iv[1] = (count >> 16) as u8;
    iv[2] = (count >> 8) as u8;
    iv[3] = count as u8;
    iv[4] = bearer << 3 | direction << 2;
    iv[5..=7].fill(0x0);
    let tmp = &iv[0..8].to_vec();
    iv[8..16].copy_from_slice(tmp);

    encryption_xor(ck, u128::from_ne_bytes(iv), length, ibs)
}

#[cfg(test)]
mod tests {
    use crate::eea3_128::eea3_128;

    /// 3GPP LTE Example 1
    /// FROM https://openstd.samr.gov.cn/bzgk/gb/newGbInfo?hcno=5D3CBA3ADEC7989344BD1E63006EF2B3
    #[test]
    fn test_1() {
        let ck = 0x17_3d_14_ba_50_03_73_1d_7a_60_04_94_70_f0_0a_29;
        let count = 0x66035492;
        let bearer = 0xf;
        let direction = 0x0;
        let length = 0xc1;
        let ibs: [u8; 28] = [
            0x6c, 0xf6, 0x53, 0x40, 0x73, 0x55, 0x52, 0xab, 0x0c, 0x97, 0x52, 0xfa, 0x6f, 0x90,
            0x25, 0xfe, 0x0b, 0xd6, 0x75, 0xd9, 0x00, 0x58, 0x75, 0xb2, 0x00, 0x00, 0x00, 0x00,
        ];
        let obs: [u8; 28] = [
            0xa6, 0xc8, 0x5f, 0xc6, 0x6a, 0xfb, 0x85, 0x33, 0xaa, 0xfc, 0x25, 0x18, 0xdf, 0xe7,
            0x84, 0x94, 0x0e, 0xe1, 0xe4, 0xb0, 0x30, 0x23, 0x8c, 0xc8, 0x00, 0x00, 0x00, 0x00,
        ];

        assert_eq!(
            eea3_128(count, bearer, direction, ck, length, &ibs),
            &obs[..]
        )
    }

    /// 3GPP LTE Example 2
    /// FROM https://openstd.samr.gov.cn/bzgk/gb/newGbInfo?hcno=5D3CBA3ADEC7989344BD1E63006EF2B3
    #[test]
    fn test_2() {
        let ck: u128 = 0xe5_bd_3e_a0_eb_55_ad_e8_66_c6_ac_58_bd_54_30_2a;
        let count = 0x56823;
        let bearer = 0x18;
        let direction = 0x1;
        let length = 0x320;
        let ibs: [u8; 100] = [
            0x14, 0xa8, 0xef, 0x69, 0x3d, 0x67, 0x85, 0x07, 0xbb, 0xe7, 0x27, 0x0a, 0x7f, 0x67,
            0xff, 0x50, 0x06, 0xc3, 0x52, 0x5b, 0x98, 0x07, 0xe4, 0x67, 0xc4, 0xe5, 0x60, 0x00,
            0xba, 0x33, 0x8f, 0x5d, 0x42, 0x95, 0x59, 0x03, 0x67, 0x51, 0x82, 0x22, 0x46, 0xc8,
            0x0d, 0x3b, 0x38, 0xf0, 0x7f, 0x4b, 0xe2, 0xd8, 0xff, 0x58, 0x05, 0xf5, 0x13, 0x22,
            0x29, 0xbd, 0xe9, 0x3b, 0xbb, 0xdc, 0xaf, 0x38, 0x2b, 0xf1, 0xee, 0x97, 0x2f, 0xbf,
            0x99, 0x77, 0xba, 0xda, 0x89, 0x45, 0x84, 0x7a, 0x2a, 0x6c, 0x9a, 0xd3, 0x4a, 0x66,
            0x75, 0x54, 0xe0, 0x4d, 0x1f, 0x7f, 0xa2, 0xc3, 0x32, 0x41, 0xbd, 0x8f, 0x01, 0xba,
            0x22, 0x0d,
        ];
        let obs: [u8; 100] = [
            0x13, 0x1d, 0x43, 0xe0, 0xde, 0xa1, 0xbe, 0x5c, 0x5a, 0x1b, 0xfd, 0x97, 0x1d, 0x85,
            0x2c, 0xbf, 0x71, 0x2d, 0x7b, 0x4f, 0x57, 0x96, 0x1f, 0xea, 0x32, 0x08, 0xaf, 0xa8,
            0xbc, 0xa4, 0x33, 0xf4, 0x56, 0xad, 0x09, 0xc7, 0x41, 0x7e, 0x58, 0xbc, 0x69, 0xcf,
            0x88, 0x66, 0xd1, 0x35, 0x3f, 0x74, 0x86, 0x5e, 0x80, 0x78, 0x1d, 0x20, 0x2d, 0xfb,
            0x3e, 0xcf, 0xf7, 0xfc, 0xbc, 0x3b, 0x19, 0x0f, 0xe8, 0x2a, 0x20, 0x4e, 0xd0, 0xe3,
            0x50, 0xfc, 0x0f, 0x6f, 0x26, 0x13, 0xb2, 0xf2, 0xbc, 0xa6, 0xdf, 0x5a, 0x47, 0x3a,
            0x57, 0xa4, 0xa0, 0x0d, 0x98, 0x5e, 0xba, 0xd8, 0x80, 0xd6, 0xf2, 0x38, 0x64, 0xa0,
            0x7b, 0x01,
        ];

        assert_eq!(eea3_128(count, bearer, direction, ck, length, &ibs), &obs);
    }

    /// 3GPP LTE Example 3
    /// FROM https://openstd.samr.gov.cn/bzgk/gb/newGbInfo?hcno=5D3CBA3ADEC7989344BD1E63006EF2B3
    #[test]
    fn test_3() {
        let ck = u128::from_be_bytes([
            0xe1, 0x3f, 0xed, 0x21, 0xb4, 0x6e, 0x4e, 0x7e, 0xc3, 0x12, 0x53, 0xb2, 0xbb, 0x17,
            0xb3, 0xe0,
        ]);
        let count = 0x2738cdaa;
        let bearer = 0x1a;
        let direction = 0x0;
        let length = 0xfb3;
        let ibs: [u32; 126] = [
            0x8d74e20d, 0x54894e06, 0xd3cb13cb, 0x3933065e, 0x8674be62, 0xadb1c72b, 0x3a646965,
            0xab63cb7b, 0x7854dfdc, 0x27e84929, 0xf49c64b8, 0x72a490b1, 0x3f957b64, 0x827e71f4,
            0x1fbd4269, 0xa42c97f8, 0x24537027, 0xf86e9f4a, 0xd82d1df4, 0x51690fdd, 0x98b6d03f,
            0x3a0ebe3a, 0x312d6b84, 0x0ba5a182, 0x0b2a2c97, 0x09c090d2, 0x45ed267c, 0xf845ae41,
            0xfa975d33, 0x33ac3009, 0xfd40eba9, 0xeb5b8857, 0x14b768b6, 0x97138baf, 0x21380eca,
            0x49f644d4, 0x8689e421, 0x5760b906, 0x739f0d2b, 0x3f091133, 0xca15d981, 0xcbe401ba,
            0xf72d05ac, 0xe05cccb2, 0xd297f4ef, 0x6a5f58d9, 0x1246cfa7, 0x7215b892, 0xab441d52,
            0x78452795, 0xccb7f5d7, 0x9057a1c4, 0xf77f80d4, 0x6db2033c, 0xb79bedf8, 0xe60551ce,
            0x10c667f6, 0x2a97abaf, 0xabbcd677, 0x2018df96, 0xa282ea73, 0x7ce2cb33, 0x1211f60d,
            0x5354ce78, 0xf9918d9c, 0x206ca042, 0xc9b62387, 0xdd709604, 0xa50af16d, 0x8d35a890,
            0x6be484cf, 0x2e74a928, 0x99403643, 0x53249b27, 0xb4c9ae29, 0xeddfc7da, 0x6418791a,
            0x4e7baa06, 0x60fa6451, 0x1f2d685c, 0xc3a5ff70, 0xe0d2b742, 0x92e3b8a0, 0xcd6b04b1,
            0xc790b8ea, 0xd2703708, 0x540dea2f, 0xc09c3da7, 0x70f65449, 0xc84d817a, 0x4f551055,
            0xe19ab850, 0x18a0028b, 0x71a144d9, 0x6791e9a3, 0x57793350, 0x4eee0060, 0x340c69d2,
            0x74e1bf9d, 0x805dcbcc, 0x1a6faa97, 0x6800b6ff, 0x2b671dc4, 0x63652fa8, 0xa33ee509,
            0x74c1c21b, 0xe01eabb2, 0x16743026, 0x9d72ee51, 0x1c9dde30, 0x797c9a25, 0xd86ce74f,
            0x5b961be5, 0xfdfb6807, 0x814039e7, 0x137636bd, 0x1d7fa9e0, 0x9efd2007, 0x505906a5,
            0xac45dfde, 0xed7757bb, 0xee745749, 0xc2963335, 0x0bee0ea6, 0xf409df45, 0x80160000,
        ];
        let obs: [u32; 126] = [
            0x94eaa4aa, 0x30a57137, 0xddf09b97, 0xb25618a2, 0x0a13e2f1, 0x0fa5bf81, 0x61a879cc,
            0x2ae797a6, 0xb4cf2d9d, 0xf31debb9, 0x905ccfec, 0x97de605d, 0x21c61ab8, 0x531b7f3c,
            0x9da5f039, 0x31f8a064, 0x2de48211, 0xf5f52ffe, 0xa10f392a, 0x04766998, 0x5da454a2,
            0x8f080961, 0xa6c2b62d, 0xaa17f33c, 0xd60a4971, 0xf48d2d90, 0x9394a55f, 0x48117ace,
            0x43d708e6, 0xb77d3dc4, 0x6d8bc017, 0xd4d1abb7, 0x7b7428c0, 0x42b06f2f, 0x99d8d07c,
            0x9879d996, 0x00127a31, 0x985f1099, 0xbbd7d6c1, 0x519ede8f, 0x5eeb4a61, 0x0b349ac0,
            0x1ea23506, 0x91756bd1, 0x05c974a5, 0x3eddb35d, 0x1d4100b0, 0x12e522ab, 0x41f4c5f2,
            0xfde76b59, 0xcb8b96d8, 0x85cfe408, 0x0d1328a0, 0xd636cc0e, 0xdc05800b, 0x76acca8f,
            0xef672084, 0xd1f52a8b, 0xbd8e0993, 0x320992c7, 0xffbae17c, 0x408441e0, 0xee883fc8,
            0xa8b05e22, 0xf5ff7f8d, 0x1b48c74c, 0x468c467a, 0x028f09fd, 0x7ce91109, 0xa570a2d5,
            0xc4d5f4fa, 0x18c5dd3e, 0x4562afe2, 0x4ef77190, 0x1f59af64, 0x5898acef, 0x088abae0,
            0x7e92d52e, 0xb2de5504, 0x5bb1b7c4, 0x164ef2d7, 0xa6cac15e, 0xeb926d7e, 0xa2f08b66,
            0xe1f759f3, 0xaee44614, 0x725aa3c7, 0x482b3084, 0x4c143ff8, 0x7b53f1e5, 0x83c50125,
            0x7dddd096, 0xb81268da, 0xa303f172, 0x34c23335, 0x41f0bb8e, 0x190648c5, 0x807c866d,
            0x71932286, 0x09adb948, 0x686f7de2, 0x94a802cc, 0x38f7fe52, 0x08f5ea31, 0x96d0167b,
            0x9bdd02f0, 0xd2a5221c, 0xa508f893, 0xaf5c4b4b, 0xb9f4f520, 0xfd84289b, 0x3dbe7e61,
            0x497a7e2a, 0x584037ea, 0x637b6981, 0x127174af, 0x57b471df, 0x4b2768fd, 0x79c1540f,
            0xb3edf2ea, 0x22cb69be, 0xc0cf8d93, 0x3d9c6fdd, 0x645e8505, 0x91cca3d6, 0x2c0cc000,
        ];
        let ibs = ibs
            .iter()
            .flat_map(|&word| word.to_be_bytes())
            .collect::<Vec<u8>>();
        let obs = obs
            .iter()
            .flat_map(|&word| word.to_be_bytes())
            .collect::<Vec<u8>>();
        assert_eq!(eea3_128(count, bearer, direction, ck, length, &ibs), obs);
    }

    /// Test Set 3 from gsma
    /// https://www.gsma.com/solutions-and-impact/technologies/security/wp-content/uploads/2019/05/eea3eia3testdatav11.pdf
    #[test]
    fn test_set_3_from_gmssl() {
        let ck = u128::from_be_bytes([
            0xd4, 0x55, 0x2a, 0x8f, 0xd6, 0xe6, 0x1c, 0xc8, 0x1a, 0x20, 0x09, 0x14, 0x1a, 0x29,
            0xc1, 0x0b,
        ]);
        let count = 0x76452ec1;
        let bearer = 0x2;
        let direction = 0x1;
        let length = 1570;
        let ibs: [u32; 50] = [
            0x38f07f4b, 0xe2d8ff58, 0x05f51322, 0x29bde93b, 0xbbdcaf38, 0x2bf1ee97, 0x2fbf9977,
            0xbada8945, 0x847a2a6c, 0x9ad34a66, 0x7554e04d, 0x1f7fa2c3, 0x3241bd8f, 0x01ba220d,
            0x3ca4ec41, 0xe074595f, 0x54ae2b45, 0x4fd97143, 0x20436019, 0x65cca85c, 0x2417ed6c,
            0xbec3bada, 0x84fc8a57, 0x9aea7837, 0xb0271177, 0x242a64dc, 0x0a9de71a, 0x8edee86c,
            0xa3d47d03, 0x3d6bf539, 0x804eca86, 0xc584a905, 0x2de46ad3, 0xfced6554, 0x3bd90207,
            0x372b27af, 0xb79234f5, 0xff43ea87, 0x0820e2c2, 0xb78a8aae, 0x61cce52a, 0x0515e348,
            0xd196664a, 0x3456b182, 0xa07c406e, 0x4a207912, 0x71cfeda1, 0x65d535ec, 0x5ea2d4df,
            0x40000000,
        ];
        let obs: [u32; 50] = [
            0x8383b022, 0x9fcc0b9d, 0x2295ec41, 0xc977e9c2, 0xbb72e220, 0x378141f9, 0xc8318f3a,
            0x270dfbcd, 0xee6411c2, 0xb3044f17, 0x6dc6e00f, 0x8960f97a, 0xfacd131a, 0xd6a3b49b,
            0x16b7babc, 0xf2a509eb, 0xb16a75dc, 0xab14ff27, 0x5dbeeea1, 0xa2b155f9, 0xd52c2645,
            0x2d0187c3, 0x10a4ee55, 0xbeaa78ab, 0x4024615b, 0xa9f5d5ad, 0xc7728f73, 0x560671f0,
            0x13e5e550, 0x085d3291, 0xdf7d5fec, 0xedded559, 0x641b6c2f, 0x585233bc, 0x71e9602b,
            0xd2305855, 0xbbd25ffa, 0x7f17ecbc, 0x042daae3, 0x8c1f57ad, 0x8e8ebd37, 0x346f71be,
            0xfdbb7432, 0xe0e0bb2c, 0xfc09bcd9, 0x6570cb0c, 0x0c39df5e, 0x29294e82, 0x703a637f,
            0x80000000,
        ];
        let ibs = ibs
            .iter()
            .flat_map(|&word| word.to_be_bytes())
            .collect::<Vec<u8>>();
        let obs = obs
            .iter()
            .flat_map(|&word| word.to_be_bytes())
            .collect::<Vec<u8>>();
        assert_eq!(eea3_128(count, bearer, direction, ck, length, &ibs), obs);
    }

    /// Test Set 3 from gsma
    /// https://www.gsma.com/solutions-and-impact/technologies/security/wp-content/uploads/2019/05/eea3eia3testdatav11.pdf
    #[test]
    fn test_set_4_from_gmssl() {
        let ck = u128::from_be_bytes([
            0xdb, 0x84, 0xb4, 0xfb, 0xcc, 0xda, 0x56, 0x3b, 0x66, 0x22, 0x7b, 0xfe, 0x45, 0x6f,
            0x0f, 0x77,
        ]);
        let count = 0xe4850fe1;
        let bearer = 0x10;
        let direction = 0x1;
        let length = 2798;
        let ibs: [u32; 88] = [
            0xe539f3b8, 0x973240da, 0x03f2b8aa, 0x05ee0a00, 0xdbafc0e1, 0x82055dfe, 0x3d7383d9,
            0x2cef40e9, 0x2928605d, 0x52d05f4f, 0x9018a1f1, 0x89ae3997, 0xce19155f, 0xb1221db8,
            0xbb0951a8, 0x53ad852c, 0xe16cff07, 0x382c93a1, 0x57de00dd, 0xb125c753, 0x9fd85045,
            0xe4ee07e0, 0xc43f9e9d, 0x6f414fc4, 0xd1c62917, 0x813f74c0, 0x0fc83f3e, 0x2ed7c45b,
            0xa5835264, 0xb43e0b20, 0xafda6b30, 0x53bfb642, 0x3b7fce25, 0x479ff5f1, 0x39dd9b5b,
            0x995558e2, 0xa56be18d, 0xd581cd01, 0x7c735e6f, 0x0d0d97c4, 0xddc1d1da, 0x70c6db4a,
            0x12cc9277, 0x8e2fbbd6, 0xf3ba52af, 0x91c9c6b6, 0x4e8da4f7, 0xa2c266d0, 0x2d001753,
            0xdf089603, 0x93c5d568, 0x88bf49eb, 0x5c16d9a8, 0x0427a416, 0xbcb597df, 0x5bfe6f13,
            0x890a07ee, 0x1340e647, 0x6b0d9aa8, 0xf822ab0f, 0xd1ab0d20, 0x4f40b7ce, 0x6f2e136e,
            0xb67485e5, 0x07804d50, 0x4588ad37, 0xffd81656, 0x8b2dc403, 0x11dfb654, 0xcdead47e,
            0x2385c343, 0x6203dd83, 0x6f9c64d9, 0x7462ad5d, 0xfa63b5cf, 0xe08acb95, 0x32866f5c,
            0xa787566f, 0xca93e6b1, 0x693ee15c, 0xf6f7a2d6, 0x89d97417, 0x98dc1c23, 0x8e1be650,
            0x733b18fb, 0x34ff880e, 0x16bbd21b, 0x47ac0000,
        ];
        let obs: [u32; 88] = [
            0x4bbfa91b, 0xa25d47db, 0x9a9f190d, 0x962a19ab, 0x323926b3, 0x51fbd39e, 0x351e05da,
            0x8b8925e3, 0x0b1cce0d, 0x12211010, 0x95815cc7, 0xcb631950, 0x9ec0d679, 0x40491987,
            0xe13f0aff, 0xac332aa6, 0xaa64626d, 0x3e9a1917, 0x519e0b97, 0xb655c6a1, 0x65e44ca9,
            0xfeac0790, 0xd2a321ad, 0x3d86b79c, 0x5138739f, 0xa38d887e, 0xc7def449, 0xce8abdd3,
            0xe7f8dc4c, 0xa9e7b733, 0x14ad310f, 0x9025e619, 0x46b3a56d, 0xc649ec0d, 0xa0d63943,
            0xdff592cf, 0x962a7efb, 0x2c8524e3, 0x5a2a6e78, 0x79d62604, 0xef268695, 0xfa400302,
            0x7e22e608, 0x30775220, 0x64bd4a5b, 0x906b5f53, 0x1274f235, 0xed506cff, 0x0154c754,
            0x928a0ce5, 0x476f2cb1, 0x020a1222, 0xd32c1455, 0xecaef1e3, 0x68fb344d, 0x1735bfbe,
            0xdeb71d0a, 0x33a2a54b, 0x1da5a294, 0xe679144d, 0xdf11eb1a, 0x3de8cf0c, 0xc0619179,
            0x74f35c1d, 0x9ca0ac81, 0x807f8fcc, 0xe6199a6c, 0x7712da86, 0x5021b04c, 0xe0439516,
            0xf1a526cc, 0xda9fd9ab, 0xbd53c3a6, 0x84f9ae1e, 0x7ee6b11d, 0xa138ea82, 0x6c5516b5,
            0xaadf1abb, 0xe36fa7ff, 0xf92e3a11, 0x76064e8d, 0x95f2e488, 0x2b5500b9, 0x3228b219,
            0x4a475c1a, 0x27f63f9f, 0xfd264989, 0xa1bc0000,
        ];
        let ibs = ibs
            .iter()
            .flat_map(|&word| word.to_be_bytes())
            .collect::<Vec<u8>>();
        let obs = obs
            .iter()
            .flat_map(|&word| word.to_be_bytes())
            .collect::<Vec<u8>>();
        assert_eq!(eea3_128(count, bearer, direction, ck, length, &ibs), obs);
    }
}
