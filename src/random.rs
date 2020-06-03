//! Random generation using linux kernel Crypto Api.
//!
//! [NIST SP800-90]: https://csrc.nist.gov/publications/detail/sp/800-90a/rev-1/final

use crate::err::Error;
use crate::internal::KcApi;

/// Type of Random number Generator
pub enum RngType {
    /// CPU Time Jitter Based Non-Physical True Random Number Generator (see [CPU-Jitter-NPTRNG.pdf](http://www.chronox.de/jent/doc/CPU-Jitter-NPTRNG.pdf))
    JitterEntropy,
    /// HMAC_DRBG based on SHA-256 without prediction resistance as specified in [NIST SP800-90A-rev1](https://csrc.nist.gov/publications/detail/sp/800-90a/rev-1/final)
    DrbgNoprHmacSha256,
    /// HMAC_DRBG based on SHA-384 without prediction resistance as specified in [NIST SP800-90A-rev1](https://csrc.nist.gov/publications/detail/sp/800-90a/rev-1/final)
    DrbgNoprHmacSha384,
    /// HMAC_DRBG based on SHA-512 without prediction resistance as specified in [NIST SP800-90A-rev1](https://csrc.nist.gov/publications/detail/sp/800-90a/rev-1/final)
    DrbgNoprHmacSha512,
    /// Hash_DRBG based on SHA-256 without prediction resistance as specified in [NIST SP800-90A-rev1](https://csrc.nist.gov/publications/detail/sp/800-90a/rev-1/final)
    DrbgNoprSha256,
    /// Hash_DRBG based on SHA-384 without prediction resistance as specified in [NIST SP800-90A-rev1](https://csrc.nist.gov/publications/detail/sp/800-90a/rev-1/final)
    DrbgNoprSha384,
    /// Hash_DRBG based on SHA-512 without prediction resistance as specified in [NIST SP800-90A-rev1](https://csrc.nist.gov/publications/detail/sp/800-90a/rev-1/final)
    DrbgNoprSha512,
    /// CTR_DRBG based on AES with 128 bits keys without prediction resistance as specified in [NIST SP800-90A-rev1](https://csrc.nist.gov/publications/detail/sp/800-90a/rev-1/final)
    DrbgNoprCtrAes128,
    /// CTR_DRBG based on AES with 192 bits keys without prediction resistance as specified in [NIST SP800-90A-rev1](https://csrc.nist.gov/publications/detail/sp/800-90a/rev-1/final)
    DrbgNoprCtrAes192,
    /// CTR_DRBG based on AES with 256 bits keys without prediction resistance as specified in [NIST SP800-90A-rev1](https://csrc.nist.gov/publications/detail/sp/800-90a/rev-1/final)
    DrbgNoprCtrAes256,
    /// HMAC_DRBG based on SHA-256 **with** prediction resistance as specified in [NIST SP800-90A-rev1](https://csrc.nist.gov/publications/detail/sp/800-90a/rev-1/final)
    DrbgPrHmacSha256,
    /// HMAC_DRBG based on SHA-384 **with** prediction resistance as specified in [NIST SP800-90A-rev1](https://csrc.nist.gov/publications/detail/sp/800-90a/rev-1/final)
    DrbgPrHmacSha384,
    /// HMAC_DRBG based on SHA-512 **with** prediction resistance as specified in [NIST SP800-90A-rev1](https://csrc.nist.gov/publications/detail/sp/800-90a/rev-1/final)
    DrbgPrHmacSha512,

    /// Hash_DRBG based on SHA-256 **with** prediction resistance as specified in [NIST SP800-90A-rev1](https://csrc.nist.gov/publications/detail/sp/800-90a/rev-1/final)
    DrbgPrSha256,
    /// Hash_DRBG based on SHA-384 **with** prediction resistance as specified in [NIST SP800-90A-rev1](https://csrc.nist.gov/publications/detail/sp/800-90a/rev-1/final)
    DrbgPrSha384,
    /// Hash_DRBG based on SHA-512 **with** prediction resistance as specified in [NIST SP800-90A-rev1](https://csrc.nist.gov/publications/detail/sp/800-90a/rev-1/final)
    DrbgPrSha512,
    /// CTR_DRBG based on AES with 128 bits keys **with** prediction resistance as specified in [NIST SP800-90A-rev1](https://csrc.nist.gov/publications/detail/sp/800-90a/rev-1/final)
    DrbgPrCtrAes128,
    /// CTR_DRBG based on AES with 192 bits keys **with** prediction resistance as specified in [NIST SP800-90A-rev1](https://csrc.nist.gov/publications/detail/sp/800-90a/rev-1/final)
    DrbgPrCtrAes192,
    /// CTR_DRBG based on AES with 256 bits keys **with** prediction resistance as specified in [NIST SP800-90A-rev1](https://csrc.nist.gov/publications/detail/sp/800-90a/rev-1/final)
    DrbgPrCtrAes256,
}

impl RngType {
    #[allow(clippy::unused_self)]
    #[must_use]
    /// Get type str to be used as type with `AF_ALG` sockets
    pub fn get_type(&self) -> &'static str {
        "rng"
    }

    #[must_use]
    /// Get name str to be used as type with `AF_ALG` sockets
    pub fn get_name(&self) -> &'static str {
        match self {
            Self::JitterEntropy => "jitterentropy_rng",
            Self::DrbgNoprHmacSha256 => "drbg_nopr_hmac_sha256",
            Self::DrbgNoprHmacSha384 => "drbg_nopr_hmac_sha384",
            Self::DrbgNoprHmacSha512 => "drbg_nopr_hmac_sha512",
            Self::DrbgNoprSha256 => "drbg_nopr_sha256",
            Self::DrbgNoprSha384 => "drbg_nopr_sha384",
            Self::DrbgNoprSha512 => "drbg_nopr_sha512",
            Self::DrbgNoprCtrAes128 => "drbg_nopr_ctr_aes128",
            Self::DrbgNoprCtrAes192 => "drbg_nopr_ctr_aes192",
            Self::DrbgNoprCtrAes256 => "drbg_nopr_ctr_aes256",
            Self::DrbgPrHmacSha256 => "drbg_pr_hmac_sha256",
            Self::DrbgPrHmacSha384 => "drbg_pr_hmac_sha384",
            Self::DrbgPrHmacSha512 => "drbg_pr_hmac_sha512",
            Self::DrbgPrSha256 => "drbg_pr_sha256",
            Self::DrbgPrSha384 => "drbg_pr_sha384",
            Self::DrbgPrSha512 => "drbg_pr_sha512",
            Self::DrbgPrCtrAes128 => "drbg_pr_ctr_aes128",
            Self::DrbgPrCtrAes192 => "drbg_pr_ctr_aes192",
            Self::DrbgPrCtrAes256 => "drbg_pr_ctr_aes256",
        }
    }

    #[must_use]
    /// Whether this random generator has prediction restistance
    pub fn has_prediction_resistance(&self) -> bool {
        match self {
            Self::DrbgNoprHmacSha256
            | Self::DrbgNoprHmacSha384
            | Self::DrbgNoprHmacSha512
            | Self::DrbgNoprSha256
            | Self::DrbgNoprSha384
            | Self::DrbgNoprSha512
            | Self::DrbgNoprCtrAes128
            | Self::DrbgNoprCtrAes192
            | Self::DrbgNoprCtrAes256 => false,
            Self::JitterEntropy
            | Self::DrbgPrHmacSha256
            | Self::DrbgPrHmacSha384
            | Self::DrbgPrHmacSha512
            | Self::DrbgPrSha256
            | Self::DrbgPrSha384
            | Self::DrbgPrSha512
            | Self::DrbgPrCtrAes128
            | Self::DrbgPrCtrAes192
            | Self::DrbgPrCtrAes256 => true,
        }
    }
}

/// Random Generator.
///
/// If the `rand_trait` feature is enabled,  it implements the [`rand_core::RngCore`](https://rust-random.github.io/rand/rand_core/trait.RngCore.html)
/// and [`rand_core::CryptoRng`](https://rust-random.github.io/rand/rand_core/trait.CryptoRng.html) traits.
///
/// # Sample usage
///
/// ```
/// # use linux_kcapi::Error;
/// use linux_kcapi::random::{RngType, Rng};
///
/// # fn get_random_bytes() -> Result<(), Error> {
/// #     let seed = [0_u8; 32];
/// #     let zero = [0_u8; 32];
/// #     let mut data = [0_u8; 32];
/// #     let mut data2 = [0_u8; 32];
/// let rng = Rng::new(&RngType::DrbgPrHmacSha256, &seed)?;
/// rng.get_bytes(&mut data)?;
/// assert_ne!(zero, data);
/// rng.get_bytes(&mut data2)?;
/// assert_ne!(data, data2);
/// #     Ok(())
/// # }
/// ```
pub struct Rng {
    api: KcApi,
}

impl Rng {
    /// Create a new random generator.
    /// # Errors
    ///  - [`Error::Sys(Errno)`](../enum.Error.html#variant.Sys)  in case of low level error
    pub fn new<T>(rng: &RngType, seed: &T) -> Result<Self, Error>
    where
        T: AsRef<[u8]> + Clone,
    {
        let mut ret = Self {
            api: KcApi::new(rng.get_type(), rng.get_name())?,
        };
        ret.api.set_key(seed)?;
        ret.api.init()?;
        Ok(ret)
    }

    /// fill destination with random bytes
    /// # Errors
    ///  - [`Error::Incomplete`](../enum.Error.html#variant.Incomplete) if destination was not totally filled
    ///  - [`Error::Sys(Errno)`](../enum.Error.html#variant.Sys)  in case of low level error
    pub fn get_bytes(&self, dest: &mut [u8]) -> Result<(), Error> {
        let sz = self.api.read(dest)?;
        if sz == dest.len() {
            Ok(())
        } else {
            Err(Error::Incomplete)
        }
    }
}

#[cfg(feature = "rand_trait")]
/// Implementation of `rand_core` crate trait.
/// # Panic
/// `next_u32`, `next_u64` and `fill_bytes` will panic in case of error
impl rand_core::RngCore for Rng {
    fn next_u32(&mut self) -> u32 {
        let mut dest = [0_u8; 4];
        self.fill_bytes(&mut dest);
        u32::from_le_bytes(dest)
    }

    fn next_u64(&mut self) -> u64 {
        let mut dest = [0_u8; 8];
        self.fill_bytes(&mut dest);
        u64::from_le_bytes(dest)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        if let Err(e) = self.try_fill_bytes(dest) {
            panic!("fill_bytes error : {}", e);
        }
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        // The kernel generates at most 128 bytes in one call.
        let chunks = dest.chunks_mut(128);
        for chunk in chunks {
            if let Err(e) = self.get_bytes(chunk) {
                return Err(e.into());
            }
        }
        Ok(())
    }
}

#[cfg(feature = "rand_trait")]
impl rand_core::CryptoRng for Rng {}

#[cfg(test)]
mod tests {
    use super::*;

    static RNG_TYPES: &[RngType] = &[
        RngType::DrbgNoprHmacSha256,
        RngType::DrbgNoprHmacSha384,
        RngType::DrbgNoprHmacSha512,
        RngType::DrbgNoprSha256,
        RngType::DrbgNoprSha384,
        RngType::DrbgNoprSha512,
        RngType::DrbgNoprCtrAes128,
        RngType::DrbgNoprCtrAes192,
        RngType::DrbgNoprCtrAes256,
        RngType::JitterEntropy,
        RngType::DrbgPrHmacSha256,
        RngType::DrbgPrHmacSha384,
        RngType::DrbgPrHmacSha512,
        RngType::DrbgPrSha256,
        RngType::DrbgPrSha384,
        RngType::DrbgPrSha512,
        RngType::DrbgPrCtrAes128,
        RngType::DrbgPrCtrAes192,
        RngType::DrbgPrCtrAes256,
    ];

    #[test]
    fn new() {
        for rng in RNG_TYPES {
            let seed = [0_u8; 32];
            assert!(Rng::new(rng, &seed).is_ok());
        }
    }

    #[test]
    fn get_random_bytes() -> Result<(), Error> {
        for rng_type in RNG_TYPES {
            let seed = [0_u8; 32];
            let zero = [0_u8; 32];
            let mut data = [0_u8; 32];
            let mut data2 = [0_u8; 32];
            let rng = Rng::new(rng_type, &seed)?;
            rng.get_bytes(&mut data)?;
            assert_ne!(zero, data);
            rng.get_bytes(&mut data2)?;
            assert_ne!(data, data2);
        }
        Ok(())
    }
}
