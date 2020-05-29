//! This crate provides tools for using crypto operation from the linux kernel.

#![deny(missing_docs)]
#![cfg_attr(feature = "cargo-clippy", deny(clippy::all))]
#![cfg_attr(feature = "cargo-clippy", deny(clippy::pedantic))]

pub mod err;
pub mod internal;

pub use err::Error;