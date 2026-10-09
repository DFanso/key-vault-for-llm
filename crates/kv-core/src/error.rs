use std::path::PathBuf;

#[derive(Debug, thiserror::Error)]
pub enum VaultError {
    #[error("a vault already exists at {0}")]
    AlreadyExists(PathBuf),
    #[error("no vault found at {0}")]
    NotFound(PathBuf),
    #[error("wrong passphrase")]
    WrongPassphrase,
    #[error("this unlock method is not set up for the vault, or no longer matches it")]
    DeviceKeyRejected,
    #[error("the vault file is corrupted or has been tampered with")]
    Corrupted,
    #[error("unsupported vault format version {0}")]
    UnsupportedVersion(u16),
    #[error("passphrase must be at least 8 characters")]
    WeakPassphrase,
    #[error(
        "invalid handle name {0:?}: use 1-63 lowercase letters, digits, '-' or '_', starting with a letter or digit"
    )]
    InvalidHandle(String),
    #[error(transparent)]
    Io(#[from] std::io::Error),
}
