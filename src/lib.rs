//! ZUC Stream Cipher Algorithms

#![deny(
    unsafe_code, //
    missing_docs,
)]
#![deny(
    clippy::all,
    clippy::pedantic,
    clippy::cargo,
    clippy::missing_docs_in_private_items
)]
#![warn(
    clippy::todo, //
)]
#![allow(
    clippy::inline_always, //
    clippy::needless_range_loop,
    clippy::module_name_repetitions,
)]
// ---
#![cfg_attr(docsrs, feature(doc_cfg))]

mod utils;
mod zuc;

mod zuc128;
pub use self::zuc128::{Zuc128, Zuc128Core};

mod eea3_128;
pub use eea3_128::{eea3_128_encrypt, xor_encrypt};

mod eia3_128;
pub use eia3_128::{eia3_128_generate_mac, generate_mac};

mod zuc256;
pub use self::zuc256::{Zuc256, Zuc256Core};

mod zuc256_mac;
pub use self::zuc256_mac::zuc256_generate_mac;

pub use cipher;
