//! Error definition for this crate

use std::error;
use std::fmt;

use log;
pub use nix::errno::Errno;

#[derive(Debug, PartialEq)]
/// KCAPI errors
pub enum Error {
  /// Error from C.
  /// See `man 3 errno`
  Sys(Errno),
  /// Operation did not complete
  Incomplete,
  /// Unknown error
  Unmanaged,
}

impl fmt::Display for Error {
  fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
    match self {
      Error::Sys(e) => write!(f, "Error from C ({})", e),
      Error::Incomplete => write!(f, "Operation did not complete"),
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

use core::num::NonZeroU32;

#[cfg(feature = "rand_trait")]
impl Into<rand_core::Error> for Error {
  fn into(self) -> rand_core::Error {
    let r = unsafe { NonZeroU32::new_unchecked(0xFFFF_FFFF) };

    match self {
      Error::Sys(e) => {
        if let Some(err) = NonZeroU32::new(e as u32) {
          rand_core::Error::from(err)
        } else {
          rand_core::Error::from(r)
        }
      }
      _ => rand_core::Error::from(r),
    }
  }
}
