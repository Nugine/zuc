#[cfg(test)]
mod tests {
    use zuc::ZUC256;

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

    static EXAMPLE2: Example = Example {
        k: [0xff; 32],
        iv: [0xff; 25],
        expected: [
            0x3356_cbae,
            0xd1a1_c18b,
            0x6baa_4ffe,
            0x343f_777c,
            0x9e15_128f,
            0x251a_b65b,
            0x949f_7b26,
            0xef71_57f2,
            0x96dd_2fa9,
            0xdf95_e3ee,
            0x7a5b_e02e,
            0xc32b_a585,
            0x505a_f316,
            0xc2f9_ded2,
            0x7cdb_d935,
            0xe441_ce11,
            0x15fd_0a80,
            0xbb7a_ef67,
            0x6898_9416,
            0xb8fa_c8c2,
        ],
    };

    #[test]
    fn examples() {
        for Example { k, iv, expected } in [&EXAMPLE1, &EXAMPLE2] {
            let mut zuc = ZUC256::new(k, iv);
            for i in 0..20 {
                assert_eq!(zuc.generate(), expected[i]);
            }
        }
    }
}
