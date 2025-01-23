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

mod mac;
mod u256;
mod zuc;

mod zuc128;
pub use self::zuc128::{Zuc128, Zuc128Core};

mod zuc128_mac;
pub use self::zuc128_mac::zuc128_generate_mac;
pub use self::zuc128_mac::Zuc128Mac;

mod eea3;
pub use self::eea3::{eea3_encrypt, zuc128_xor_encrypt};

mod eia3;
pub use self::eia3::eia3_generate_mac;
pub use self::eia3::Eia3Mac;

mod zuc256;
pub use self::zuc256::{Zuc256, Zuc256Core};

mod zuc256_mac;
pub use self::zuc256_mac::zuc256_generate_mac;
pub use self::zuc256_mac::Zuc256Mac;

pub use cipher;
