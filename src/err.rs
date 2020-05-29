//! Error definition for this crate

use std::error;
use std::fmt;

use log;
pub use nix::errno::Errno;

#[derive(Debug, PartialEq)]
/// KCAPI errors
pub enum Error {
  /// Error from C
  Sys(Errno),
  /// Unknown error
  Unmanaged,
}

impl fmt::Display for Error {
  fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
    match self {
      Error::Sys(e) => write!(f, "Error from C ({})", e),
      Error::Unmanaged => write!(f, "Unmanaged error"),
    }
  }
}

impl error::Error for Error {
  fn source(&self) -> Option<&(dyn error::Error + 'static)> {
    match self {
      _ => None, // Generic error or this module error, underlying cause isn't tracked.
    }
  }
}

impl From<nix::Error> for Error {
  fn from(e: nix::Error) -> Self {
    if let Some(errno) = e.as_errno() {
      Self::Sys(errno)
    } else {
      log::debug!("Unmanaged error {}", e);
      Self::Unmanaged
    }
  }
}

impl From<i32> for Error {
  fn from(error: i32) -> Self {
    Self::Sys(Errno::from_i32(error))
  }
}
