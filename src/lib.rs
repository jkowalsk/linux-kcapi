//! This crate provides tools for using crypto operation from the linux kernel.

#![deny(missing_docs)]
#![cfg_attr(feature = "cargo-clippy", deny(clippy::all))]
#![cfg_attr(feature = "cargo-clippy", deny(clippy::pedantic))]

mod err;
pub mod internal;
pub mod random;

pub use err::Error;
