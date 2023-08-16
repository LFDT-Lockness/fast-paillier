mod decryption_key;
mod encryption_key;
pub mod utils;

#[cfg(feature = "serde")]
mod serde;

use rug::Integer;

pub type Ciphertext = Integer;
pub type Plaintext = Integer;
pub type Nonce = Integer;

pub use self::{decryption_key::DecryptionKey, encryption_key::EncryptionKey};

#[derive(Debug, thiserror::Error)]
#[error(transparent)]
pub struct Error(#[from] Reason);

#[derive(Debug, thiserror::Error)]
enum Reason {
    #[error("p,q are invalid")]
    InvalidPQ,
    #[error("encryption error")]
    Encrypt,
    #[error("decryption error")]
    Decrypt,
    #[error("homorphic operation failed: invalid inputs")]
    Ops,
    #[error("bug occurred")]
    Bug(#[source] Bug),
}

#[derive(Debug, thiserror::Error)]
enum Bug {
    #[error("pow mod undefined")]
    PowModUndef,
    #[error("could not construct faster encryption")]
    NewFasterEncrypt,
}

impl From<Bug> for Error {
    fn from(err: Bug) -> Self {
        Error(Reason::Bug(err))
    }
}
