//! The one machine key: a hardware-wrapped P-256 key blob in the user data directory.

#[cfg(target_os = "linux")]
mod tpm;
#[cfg(target_os = "linux")]
use tpm as backend;

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
mod secure_enclave;
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
use secure_enclave as backend;

#[cfg(not(any(target_os = "linux", all(target_os = "macos", target_arch = "aarch64"))))]
compile_error!("machine-signing supports Linux with a TPM 2.0 and macOS on Apple silicon only");

use anyhow::{Context, Result};
use ssh_key::public::{EcdsaPublicKey, KeyData};
use std::path::PathBuf;

/// The name of the hardware that holds the key, for messages.
pub const HARDWARE: &str = if cfg!(target_os = "linux") {
    "TPM"
} else {
    "Secure Enclave"
};

pub struct Key {
    blob: Vec<u8>,
    pub public: KeyData,
}

pub enum Loaded {
    Existing(Key),
    Created(Key),
}

impl Key {
    /// The key blob path. The OpenSSH public key sits beside it with a `.pub` extension.
    pub fn path() -> Result<PathBuf> {
        let dir =
            dirs::data_dir().context("cannot find the user data directory: HOME is not set")?;
        Ok(dir.join("machine-signing").join("key"))
    }

    pub fn public_path() -> Result<PathBuf> {
        Ok(Self::path()?.with_extension("pub"))
    }

    pub fn load() -> Result<Key> {
        let path = Self::path()?;
        let blob = std::fs::read(&path).with_context(|| {
            format!(
                "cannot read the machine key {}. Run `machine-signing init` to create it",
                path.display()
            )
        })?;
        Self::from_blob(blob)
    }

    /// Loads the key, or creates it in the hardware when no key file exists.
    pub fn load_or_create() -> Result<Loaded> {
        let path = Self::path()?;
        if path.exists() {
            return Ok(Loaded::Existing(Self::load()?));
        }
        let blob = backend::generate()?;
        let dir = path.parent().expect("the key path has a parent");
        std::fs::create_dir_all(dir).with_context(|| format!("cannot create {}", dir.display()))?;
        std::fs::write(&path, &blob).with_context(|| format!("cannot write {}", path.display()))?;
        Ok(Loaded::Created(Self::from_blob(blob)?))
    }

    fn from_blob(blob: Vec<u8>) -> Result<Key> {
        let public = EcdsaPublicKey::from_sec1_bytes(&backend::public_key(&blob)?)?.into();
        Ok(Key { blob, public })
    }

    pub fn sign(&self, data: &[u8]) -> Result<p256::ecdsa::Signature> {
        backend::sign(&self.blob, data)
    }
}
