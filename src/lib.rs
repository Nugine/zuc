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
)]
// ---
#![cfg_attr(docsrs, feature(doc_cfg))]

/// zuc algorithms module
mod zuc;

/// zuc 128 bit
mod zuc128;
pub use self::zuc128::Zuc128;

/// zuc 256bit
mod zuc256;
pub use self::zuc256::{MacLength, Zuc256};

/// utils for bit calculate
mod utils;
