#[cfg(test)]
mod tests {
    use zuc::Zuc256;

    struct Example {
        k: [u8; 32],
        iv: [u8; 25],
        expected: [u32; 20],
    }

    static EXAMPLE1: Example = Example {
        k: [0; 32],
        iv: [0; 25],
        expected: [
            0x58d0_3ad6,
            0x2e03_2ce2,
            0xdafc_683a,
            0x39bd_cb03,
            0x52a2_bc67,
            0xf1b7_de74,
            0x163c_e3a1,
            0x01ef_5558,
            0x9639_d75b,
            0x95fa_681b,
            0x7f09_0df7,
            0x5639_1ccc,
            0x903b_7612,
            0x744d_544c,
            0x17bc_3fad,
            0x8b16_3b08,
            0x2178_7c0b,
            0x9777_5bb8,
            0x4943_c6bb,
            0xe8ad_8afd,
        ],
    };

    #[test]
    fn example_zuc_256() {
        for Example { k, iv, expected } in [&EXAMPLE1] {
            let mut zuc = Zuc256::new(k, iv);
            for i in 0..20 {
                assert_eq!(zuc.generate(), expected[i]);
            }
        }
    }
}
