#[cfg(test)]
mod tests {
    use zuc::Zuc128;

    struct Example {
        k: [u8; 16],
        iv: [u8; 16],
        expected: [u32; 2],
    }

    static EXAMPLE1: Example = Example {
        k: [0; 16],
        iv: [0; 16],
        expected: [0x27be_de74, 0x0180_82da],
    };

    #[test]
    fn examples_zuc_128() {
        for Example { k, iv, expected } in [&EXAMPLE1] {
            let mut zuc = Zuc128::new(k, iv);
            for i in 0..2 {
                assert_eq!(zuc.generate(), expected[i]);
            }
        }
    }
}
