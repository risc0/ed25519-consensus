#![doc(html_root_url = "https://docs.rs/ed25519-consensus/2.1.0")]
#![doc = include_str!("../README.md")]
#![deny(missing_docs)]
#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(feature = "std")]
pub mod batch;
mod error;
mod signature;
mod signing_key;
mod verification_key;

use curve25519_dalek::digest::generic_array::typenum::U64;
use curve25519_dalek::Scalar;
pub use error::Error;
use sha2::Digest;
pub use signature::Signature;
pub use signing_key::SigningKey;
pub use verification_key::{VerificationKey, VerificationKeyBytes};

/// Given we are using curve25519-dalek rather than the ng variant, we use the convenience function
/// added only to ng:
/// https://docs.rs/curve25519-dalek-ng/latest/src/curve25519_dalek_ng/scalar.rs.html#629
pub(crate) fn scalar_from_hash<D>(hash: D) -> Scalar
where
    D: Digest<OutputSize = U64>,
{
    let mut output = [0u8; 64];
    output.copy_from_slice(hash.finalize().as_slice());
    Scalar::from_bytes_mod_order_wide(&output)
}
