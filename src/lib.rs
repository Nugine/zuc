//! ZUC Stream Cipher Algorithms

#![deny(unsafe_code, missing_docs)]
#![deny(
    clippy::all,
    clippy::pedantic,
    clippy::cargo,
    clippy::missing_docs_in_private_items
)]
#![allow(clippy::inline_always)]
// ---
#![cfg_attr(docsrs, feature(doc_cfg))]

mod zuc;
pub use self::zuc::ZUC;
mod zuc128;
pub use self::zuc128::ZUC128;
mod zuc256;
pub use self::zuc256::{MacLength, ZUC256};

mod utils;
mod zuc_data;
