//! ZUC Stream Cipher Algorithms
//!
//! ## Examples
//!
//! Encrypt and decrypt with the RustCrypto stream cipher traits:
//!
//! ```
//! use cipher::{KeyIvInit, StreamCipher};
//! use zuc::zuc128::Zuc128StreamCipher;
//!
//! let key_bytes = [0u8; 16];
//! let iv_bytes = [0u8; 16];
//! let mut data = *b"hello world 123";
//!
//! let key = cipher::Key::<Zuc128StreamCipher>::from_slice(&key_bytes);
//! let iv = cipher::Iv::<Zuc128StreamCipher>::from_slice(&iv_bytes);
//!
//! let mut cipher = Zuc128StreamCipher::new(key, iv);
//! cipher.apply_keystream(&mut data);
//!
//! // Applying the keystream again restores the plaintext.
//! let mut cipher = Zuc128StreamCipher::new(key, iv);
//! cipher.apply_keystream(&mut data);
//!
//! assert_eq!(&data, b"hello world 123");
//! ```
//!
//! Compute a 128-EIA3 integrity tag:
//!
//! ```
//! use const_str::hex;
//! use zuc::eia3::Eia3Mac;
//!
//! let count = 0x561e_b2dd;
//! let bearer = 0x14;
//! let direction = 0;
//! let ik = &hex!("47 05 41 25 56 1e b2 dd a9 40 59 da 05 09 78 50");
//! let msg = &hex!("00000000 00000000 00000000");
//! let bitlen = 90;
//!
//! let mac = Eia3Mac::compute(count, bearer, direction, ik, msg, bitlen);
//! assert_eq!(mac, 0x6719_a088);
//! ```

#![no_std]
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
    pub use self::mac::Zuc128Mac;
    pub use self::stream_cipher::{zuc128_xor_inplace, Zuc128StreamCipher};
}

pub mod zuc256 {
    //! ZUC256 Algorithms
    //! ([ZUC256-version1.1](http://www.is.cas.cn/ztzl2016/zouchongzhi/201801/W020180416526664982687.pdf))

    mod keystream;
    mod mac;
    mod stream_cipher;

    pub use self::keystream::Zuc256Keystream;
    pub use self::mac::Zuc256Mac;
    pub use self::stream_cipher::Zuc256StreamCipher;
}

pub mod eea3 {
    //! 128-EEA3 Algorithms
    //! ([EEA3-EIA3-specification](https://www.gsma.com/solutions-and-impact/technologies/security/wp-content/uploads/2019/05/EEA3_EIA3_specification_v1_8.pdf))

    mod keystream;
    mod stream_cipher;

    pub use self::keystream::Eea3Keystream;
    pub use self::stream_cipher::{eea3_xor_inplace, Eea3StreamCipher};
}

pub mod eia3 {
    //! 128-EIA3 Algorithms
    //! ([EEA3-EIA3-specification](https://www.gsma.com/solutions-and-impact/technologies/security/wp-content/uploads/2019/05/EEA3_EIA3_specification_v1_8.pdf))

    mod mac;

    pub use self::mac::Eia3Mac;
}

pub use cipher;
pub use digest;
