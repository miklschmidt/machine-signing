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
use std::io::Write as _;
use std::os::unix::fs::OpenOptionsExt as _;
use std::path::{Path, PathBuf};

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
        Self::from_blob(blob).with_context(|| {
            format!(
                "cannot use the machine key {}. If it comes from another machine or is damaged, \
                 delete it and run `machine-signing init` to create a new key",
                path.display()
            )
        })
    }

    /// Loads the key, or creates it in the hardware when no key file exists. With `touch_id`, a
    /// new key needs Touch ID or the password for each signature.
    pub fn load_or_create(touch_id: bool) -> Result<Loaded> {
        let path = Self::path()?;
        if path.exists() {
            return Ok(Loaded::Existing(Self::load()?));
        }
        let blob = backend::generate(touch_id)?;
        write_key_file(&path, &blob)?;
        Ok(Loaded::Created(Self::from_blob(blob)?))
    }

    fn from_blob(blob: Vec<u8>) -> Result<Key> {
        let public = EcdsaPublicKey::from_sec1_bytes(&backend::public_key(&blob)?)?.into();
        Ok(Key { blob, public })
    }

    /// Whether each signature needs Touch ID or the password. This never shows a prompt.
    pub fn needs_touch_id(&self) -> Result<bool> {
        backend::needs_touch_id(&self.blob)
    }

    pub fn sign(&self, data: &[u8]) -> Result<p256::ecdsa::Signature> {
        backend::sign(&self.blob, data)
    }
}

/// Writes a new key file that only the user can read: on this machine, whoever reads the blob can
/// sign with the key. A failed write removes the file, so it never holds a partial blob.
fn write_key_file(path: &Path, blob: &[u8]) -> Result<()> {
    let dir = path.parent().expect("the key path has a parent");
    std::fs::create_dir_all(dir).with_context(|| format!("cannot create {}", dir.display()))?;
    let written = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .and_then(|mut file| {
            file.write_all(blob).inspect_err(|_| {
                let _ = std::fs::remove_file(path);
            })
        });
    written.with_context(|| format!("cannot write {}", path.display()))
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt as _;

    #[test]
    fn only_the_user_can_read_the_key_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("machine-signing").join("key");
        super::write_key_file(&path, b"blob").unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"blob");
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }
}
