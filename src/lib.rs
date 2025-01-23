//! ZUC Stream Cipher Algorithms

#![deny(
    unsafe_code, //
    missing_docs,
)]
#![deny(clippy::all, clippy::pedantic, clippy::cargo)]
#![warn(
    clippy::todo, //
)]
#![allow(
    clippy::inline_always, //
    clippy::needless_range_loop,
    clippy::module_name_repetitions,
    clippy::multiple_crate_versions,
)]
// ---
#![cfg_attr(docsrs, feature(doc_cfg))]

mod internal {
    pub mod u256;
    pub mod zuc;

    pub mod keystream;
    pub mod mac;
    pub mod stream_cipher;
}

pub mod zuc128 {
    //! ZUC128 Algorithms
    //! ([GB/T 33133.1-2016](https://openstd.samr.gov.cn/bzgk/gb/newGbInfo?hcno=8C41A3AEECCA52B5C0011C8010CF0715))

    mod keystream;
    mod mac;
    mod stream_cipher;

    pub use self::keystream::Zuc128Keystream;
    pub use self::mac::{zuc128_generate_mac, Zuc128Mac};
    pub use self::stream_cipher::{zuc128_xor_encrypt, Zuc128StreamCipher};
}

pub mod zuc256 {
    //! ZUC256 Algorithms
    //! ([ZUC256-version1.1](http://www.is.cas.cn/ztzl2016/zouchongzhi/201801/W020180416526664982687.pdf))

    mod keystream;
    mod mac;
    mod stream_cipher;

    pub use self::keystream::Zuc256Keystream;
    pub use self::mac::{zuc256_generate_mac, Zuc256Mac};
    pub use self::stream_cipher::Zuc256StreamCipher;
}

pub mod eea3 {
    //! 128-EEA3 Algorithms
    //! ([EEA3-EIA3-specification](https://www.gsma.com/solutions-and-impact/technologies/security/wp-content/uploads/2019/05/EEA3_EIA3_specification_v1_8.pdf))

    mod keystream;
    mod stream_cipher;

    pub use self::keystream::Eea3Keystream;
    pub use self::stream_cipher::{eea3_encrypt, Eea3StreamCipher};
}

pub mod eia3 {
    //! 128-EIA3 Algorithms
    //! ([EEA3-EIA3-specification](https://www.gsma.com/solutions-and-impact/technologies/security/wp-content/uploads/2019/05/EEA3_EIA3_specification_v1_8.pdf))

    mod mac;

    pub use self::mac::{eia3_generate_mac, Eia3Mac};
}

pub use cipher;
pub use digest;
