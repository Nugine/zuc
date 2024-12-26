//! ZUC Confidentiality Algorithms

use crate::Zuc128Core;

/// t xor keystream in EIA3
#[inline(always)]
fn eia3_xor_t(bits: &mut u32, key: &mut u64, t: &mut u32) {
    let k = if *bits & 0x8000_0000 != 0 {
        (*key >> 32) as u32
    } else {
        0
    };
    *t ^= k;
    *bits <<= 1;
    *key <<= 1;
}

/// ZUC generate MAC algorithm
/// ([GB/T 33133.3-2021](http://c.gb688.cn/bzgk/gb/showGb?type=online&hcno=C6D60AE0A7578E970EF2280ABD49F4F0))
///
/// Input:
/// - `ik`:         128bit  integrity key
/// - `iv`:         128bit  initial vector
/// - `length`:     32bit   The number of bits to be encrypted/decrypted.
/// - `m`:          the input message
///
/// Output:
/// - `u32`:        MAC(Message Authentication Code)
///
/// # Panics
/// + Panics if `length` is greater than the length of `m`
/// + Panics if `length` is greater than `usize::MAX`.
#[allow(clippy::cast_possible_truncation)]
#[must_use]
pub fn generate_mac(ik: &[u8; 16], iv: &[u8; 16], length: u32, m: &[u8]) -> u32 {
    let bitlen = usize::try_from(length).expect("`length` is greater than `usize::MAX`");
    assert!(
        bitlen <= m.len() * 8,
        "`length` is greater than the length of `m`"
    );

    let mut zuc = Zuc128Core::new(ik, iv);

    let mut t: u32 = 0;

    let mut key = {
        let k0 = zuc.generate();
        let k1 = zuc.generate();
        (u64::from(k0) << 32) | u64::from(k1)
    };

    for chunk in m[..(bitlen / 32 * 4)].chunks_exact(4) {
        let mut bits = u32::from_be_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);

        for _ in 0..32 {
            eia3_xor_t(&mut bits, &mut key, &mut t);
        }

        key |= u64::from(zuc.generate());
    }

    if bitlen % 32 == 0 {
        t ^= (key >> 32) as u32;
        t ^= key as u32;
    } else {
        let i = bitlen / 32 * 4;

        let mut bits = match (bitlen % 32) / 8 {
            0 => u32::from_be_bytes([m[i], 0, 0, 0]),
            1 => u32::from_be_bytes([m[i], m[i + 1], 0, 0]),
            2 => u32::from_be_bytes([m[i], m[i + 1], m[i + 2], 0]),
            3 => u32::from_be_bytes([m[i], m[i + 1], m[i + 2], m[i + 3]]),
            _ => unreachable!(),
        };

        for _ in 0..(bitlen % 32) {
            eia3_xor_t(&mut bits, &mut key, &mut t);
        }

        t ^= (key >> 32) as u32;
        t ^= zuc.generate();
    }

    t
}

/// 128-EIA3: 3GPP confidentiality algorithm
/// ([EEA3-EIA3-specification](https://www.gsma.com/solutions-and-impact/technologies/security/wp-content/uploads/2019/05/EEA3_EIA3_specification_v1_8.pdf))
///
/// Input:
/// - `count`:        32bit   counter
/// - `bearer`:       5bit    carrier layer identification
/// - `direction`:    1bit    transmission direction identification
/// - `ik`:           128bit  integrity key
/// - `length`:       32bit   bit length of plaintext information stream
/// - `m`:            the input message
///
/// Output:
/// - `u32`:        MAC(Message Authentication Code)
///
/// # Panics
/// + Panics if `length` is greater than the length of `m`
/// + Panics if `length` is greater than `usize::MAX`.
#[must_use]
pub fn eia3_128_generate_mac(
    count: u32,
    bearer: u8,
    direction: u8,
    ik: &[u8; 16],
    length: u32,
    m: &[u8],
) -> u32 {
    let mut iv: [u8; 16] = [0; 16];
    let count: [u8; 4] = count.to_be_bytes();
    let bearer = bearer & 0x1f;
    let direction = direction & 0x01;
    iv[0] = count[0];
    iv[1] = count[1];
    iv[2] = count[2];
    iv[3] = count[3];
    iv[4] = bearer << 3;
    iv[8] = iv[0] ^ (direction << 7);
    iv[9] = iv[1];
    iv[10] = iv[2];
    iv[11] = iv[3];
    iv[12] = iv[4];
    iv[14] = iv[6] ^ (direction << 7);
    generate_mac(ik, &iv, length, m)
}

#[cfg(test)]
mod tests {
    use super::*;

    use const_str::hex;

    struct Example {
        ik: [u8; 16],
        count: u32,
        bearer: u8,
        direction: u8,
        length: u32,
        m: &'static [u8],
        mac: u32,
    }

    /// Test Set 1
    /// FROM <https://www.gsma.com/solutions-and-impact/technologies/security/wp-content/uploads/2019/05/eea3eia3testdatav11.pdf>
    ///
    /// Example 1
    /// FROM <https://openstd.samr.gov.cn/bzgk/gb/newGbInfo?hcno=C6D60AE0A7578E970EF2280ABD49F4F0>
    static EXAMPLE1: Example = Example {
        ik: hex!("00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"),
        count: 0x0,
        bearer: 0x0,
        direction: 0,
        length: 1,
        m: &hex!("00000000"),
        mac: 0xc8a9_595e,
    };

    /// Test Set 2
    /// FROM <https://www.gsma.com/solutions-and-impact/technologies/security/wp-content/uploads/2019/05/eea3eia3testdatav11.pdf>
    ///
    /// Example 2
    /// FROM <https://openstd.samr.gov.cn/bzgk/gb/newGbInfo?hcno=C6D60AE0A7578E970EF2280ABD49F4F0>
    static EXAMPLE2: Example = Example {
        ik: hex!("47 05 41 25 56 1e b2 dd a9 40 59 da 05 09 78 50"),
        count: 0x561e_b2dd,
        bearer: 0x14,
        direction: 0,
        length: 90,
        m: &hex!("00000000 00000000 00000000"),
        mac: 0x6719_a088,
    };

    /// Test Set 3
    /// FROM <https://www.gsma.com/solutions-and-impact/technologies/security/wp-content/uploads/2019/05/eea3eia3testdatav11.pdf>
    ///
    /// Example 3
    /// FROM <https://openstd.samr.gov.cn/bzgk/gb/newGbInfo?hcno=C6D60AE0A7578E970EF2280ABD49F4F0>
    static EXAMPLE3: Example = Example {
        ik: hex!("c9 e6 ce c4 60 7c 72 db 00 0a ef a8 83 85 ab 0a"),
        count: 0xa940_59da,
        bearer: 0xa,
        direction: 1,
        length: 577,
        m: &hex!([
            "983b41d4 7d780c9e 1ad11d7e b70391b1 de0b35da 2dc62f83 e7b78d63 06ca0ea0",
            "7e941b7b e91348f9 fcb170e2 217fecd9 7f9f68ad b16e5d7d 21e569d2 80ed775c ",
            "ebde3f40 93c53881 00000000"
        ]),
        mac: 0xfae8_ff0b,
    };

    /// Test Set 4
    /// FROM <https://www.gsma.com/solutions-and-impact/technologies/security/wp-content/uploads/2019/05/eea3eia3testdatav11.pdf>
    ///
    /// Example 4
    /// FROM <https://openstd.samr.gov.cn/bzgk/gb/newGbInfo?hcno=C6D60AE0A7578E970EF2280ABD49F4F0>
    static EXAMPLE4: Example = Example {
        ik: hex!("c8 a4 82 62 d0 c2 e2 ba c4 b9 6e f7 7e 80 ca 59"),
        count: 0x0509_7850,
        bearer: 0x10,
        direction: 1,
        length: 2079,
        m: &hex!([
            "b546430b f87b4f1e e834704c d6951c36 e26f108c f731788f 48dc34f1 678c0522",
            "1c8fa7ff 2f39f477 e7e49ef6 0a4ec2c3 de24312a 96aa26e1 cfba5756 3838b297",
            "f47e8510 c779fd66 54b14338 6fa639d3 1edbd6c0 6e47d159 d94362f2 6aeeedee",
            "0e4f49d9 bf841299 5415bfad 56ee82d1 ca7463ab f085b082 b09904d6 d990d43c",
            "f2e062f4 0839d932 48b1eb92 cdfed530 0bc14828 0430b6d0 caa094b6 ec8911ab",
            "7dc36824 b824dc0a f6682b09 35fde7b4 92a14dc2 f4364803 8da2cf79 170d2d50",
            "133fd494 16cb6e33 bea90b8b f4559b03 732a01ea 290e6d07 4f79bb83 c10e5800",
            "15cc1a85 b36b5501 046e9c4b dcae5135 690b8666 bd54b7a7 03ea7b6f 220a5469",
            "a568027e "
        ]),
        mac: 0x004a_c4d6,
    };

    /// Test Set 5
    /// FROM <https://www.gsma.com/solutions-and-impact/technologies/security/wp-content/uploads/2019/05/eea3eia3testdatav11.pdf>
    ///
    /// Example 5
    /// FROM <https://openstd.samr.gov.cn/bzgk/gb/newGbInfo?hcno=C6D60AE0A7578E970EF2280ABD49F4F0>
    static EXAMPLE5: Example = Example {
        ik: hex!("6b 8b 08 ee 79 e0 b5 98 2d 6d 12 8e a9 f2 20 cb"),
        count: 0x561e_b2dd,
        bearer: 0x1c,
        direction: 0,
        length: 5670,
        m: &hex!([
            "5bad7247 10ba1c56 d5a315f8 d40f6e09 3780be8e 8de07b69 92432018 e08ed96a",
            "5734af8b ad8a575d 3a1f162f 85045cc7 70925571 d9f5b94e 454a77c1 6e72936b",
            "f016ae15 7499f054 3b5d52ca a6dbeab6 97d2bb73 e41b8075 dce79b4b 86044f66",
            "1d4485a5 43dd7860 6e0419e8 059859d3 cb2b67ce 0977603f 81ff839e 33185954",
            "4cfbc8d0 0fef1a4c 8510fb54 7d6b06c6 11ef44f1 bce107cf a45a06aa b360152b",
            "28dc1ebe 6f7fe09b 0516f9a5 b02a1bd8 4bb0181e 2e89e19b d8125930 d178682f",
            "3862dc51 b636f04e 720c47c3 ce51ad70 d94b9b22 55fbae90 6549f499 f8c6d399",
            "47ed5e5d f8e2def1 13253e7b 08d0a76b 6bfc68c8 12f375c7 9b8fe5fd 85976aa6",
            "d46b4a23 39d8ae51 47f680fb e70f978b 38effd7b 2f7866a2 2554e193 a94e98a6",
            "8b74bd25 bb2b3f5f b0a5fd59 887f9ab6 8159b717 8d5b7b67 7cb546bf 41eadca2",
            "16fc1085 0128f8bd ef5c8d89 f96afa4f a8b54885 565ed838 a950fee5 f1c3b0a4",
            "f6fb71e5 4dfd169e 82cecc72 66c850e6 7c5ef0ba 960f5214 060e71eb 172a75fc",
            "1486835c bea65344 65b055c9 6a72e410 52241823 25d83041 4b40214d aa8091d2",
            "e0fb010a e15c6de9 0850973b df1e423b e148a237 b87a0c9f 34d4b476 05b803d7",
            "43a86a90 399a4af3 96d3a120 0a62f3d9 507962e8 e5bee6d3 da2bb3f7 237664ac",
            "7a292823 900bc635 03b29e80 d63f6067 bf8e1716 ac25beba 350deb62 a99fe031",
            "85eb4f69 937ecd38 7941fda5 44ba67db 09117749 38b01827 bcc69c92 b3f772a9",
            "d2859ef0 03398b1f 6bbad7b5 74f7989a 1d10b2df 798e0dbf 30d65874 64d24878",
            "cd00c0ea ee8a1a0c c753a279 79e11b41 db1de3d5 038afaf4 9f5c682c 3748d8a3",
            "a9ec54e6 a371275f 1683510f 8e4f9093 8f9ab6e1 34c2cfdf 4841cba8 8e0cff2b",
            "0bcc8e6a dcb71109 b5198fec f1bb7e5c 531aca50 a56a8a3b 6de59862 d41fa113",
            "d9cd9578 08f08571 d9a4bb79 2af271f6 cc6dbb8d c7ec36e3 6be1ed30 8164c31c",
            "7c0afc54 1c000000 "
        ]),
        mac: 0x0ca1_2792,
    };

    #[test]
    fn examples() {
        let examples = [&EXAMPLE1, &EXAMPLE2, &EXAMPLE3, &EXAMPLE4, &EXAMPLE5];
        for x in examples {
            let mac = eia3_128_generate_mac(x.count, x.bearer, x.direction, &x.ik, x.length, x.m);
            assert_eq!(mac, x.mac);
        }
    }

    #[should_panic(expected = "`length` is greater than the length of `m`")]
    #[test]
    fn invalid_input() {
        let x = &EXAMPLE2;
        let _ = eia3_128_generate_mac(x.count, x.bearer, x.direction, &x.ik, x.length * 2, x.m);
    }

    #[allow(clippy::cast_possible_truncation)]
    #[test]
    fn full_bitlen() {
        let x = &EXAMPLE5;
        let length = x.m.len() as u32 * 8;
        let mac = eia3_128_generate_mac(x.count, x.bearer, x.direction, &x.ik, length, x.m);
        assert_eq!(mac, 0x2592_99ab); // generated from GmSSL
    }

    #[test]
    fn zero_bitlen() {
        let x = &EXAMPLE5;
        let length = 0;
        let mac = eia3_128_generate_mac(x.count, x.bearer, x.direction, &x.ik, length, x.m);
        assert_eq!(mac, 0x0787_bab1); // generated from GmSSL
    }
}
