# ZUC

[![Latest Version]][crates.io]
[![Documentation]][docs.rs] 
![License]

[crates.io]: https://crates.io/crates/zuc
[Latest Version]: https://img.shields.io/crates/v/zuc.svg
[Documentation]: https://docs.rs/zuc/badge.svg
[docs.rs]: https://docs.rs/zuc
[License]: https://img.shields.io/crates/l/zuc.svg

Documentation: <https://docs.rs/zuc>

## Goals

+ **Correct**: Our implementation exactly matches the specification.
+ **Fast**: We are happy to make the performance as high as possible.
+ **Safe**: No `unsafe` code by default, unless you enable corresponding features.
+ **RustCrypto compatible**: You can use it with RustCrypto trait definitions.

## References

- **ZUC 128**: [GB/T 33133.1-2016](https://openstd.samr.gov.cn/bzgk/gb/newGbInfo?hcno=8C41A3AEECCA52B5C0011C8010CF0715)
- **128-EEA3**: [GB/T 33133.2-2021](https://openstd.samr.gov.cn/bzgk/gb/newGbInfo?hcno=5D3CBA3ADEC7989344BD1E63006EF2B3), [EEA3-EIA3-specification](https://www.gsma.com/solutions-and-impact/technologies/security/wp-content/uploads/2019/05/EEA3_EIA3_specification_v1_8.pdf)
- **128-EIA3**: [GB/T 33133.3-2021](https://openstd.samr.gov.cn/bzgk/gb/newGbInfo?hcno=C6D60AE0A7578E970EF2280ABD49F4F0)
- **ZUC 256**: [ZUC256-version1.1](http://www.is.cas.cn/ztzl2016/zouchongzhi/201801/W020180416526664982687.pdf)
- **ZUC 256 Addendum**: [ZUC256-addendum](http://www.is.cas.cn/ztzl2016/zouchongzhi/201801/W020220926381349696866.pdf) (unimplemented)
- **ZUC 256 New Initialization**: [ZUC256-new-initialization](http://www.is.cas.cn/ztzl2016/zouchongzhi/201801/W020230201389233346416.pdf) (unimplemented)

## Contributing

+ [Development Guide](./CONTRIBUTING.md)
