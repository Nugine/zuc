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
)]
// ---
#![cfg_attr(docsrs, feature(doc_cfg))]

mod zuc;

mod zuc128;
pub use self::zuc128::Zuc128;

mod zuc256;
pub use self::zuc256::Zuc256;

mod utils;
