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
    clippy::module_name_repetitions
)]
// ---
#![cfg_attr(docsrs, feature(doc_cfg))]

mod zuc128;

pub use self::zuc128::{Zuc128, Zuc128Core};
pub use cipher;
