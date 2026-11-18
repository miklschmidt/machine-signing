//! The preferred key: a key in the SSH agent, such as a YubiKey PIV key, that signs instead of the
//! machine key whenever the agent can sign with it.

use crate::key::Key;
use anyhow::{Context, Result, bail};
use ssh_key::{HashAlg, PublicKey, SshSig};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// How long the agent may take to sign, including a PIN entry or a YubiKey touch.
const TIMEOUT: Duration = Duration::from_secs(30);

/// `prefer.pub` beside the machine key. The file exists only while a key is preferred.
pub fn path() -> Result<PathBuf> {
    Ok(Key::path()?.with_file_name("prefer.pub"))
}

pub fn load() -> Result<Option<PublicKey>> {
    let path = path()?;
    if !path.exists() {
        return Ok(None);
    }
    let key = PublicKey::read_openssh_file(&path)
        .with_context(|| format!("cannot read the preferred key {}", path.display()))?;
    Ok(Some(key))
}

pub fn set(source: &Path, machine: &Key) -> Result<PublicKey> {
    let key = PublicKey::read_openssh_file(source).with_context(|| {
        format!(
            "cannot read an OpenSSH public key from {}",
            source.display()
        )
    })?;
    if key.key_data() == &machine.public {
        bail!(
            "{} is the machine key. Prefer a key that the SSH agent holds, such as a YubiKey key",
            source.display()
        );
    }
    let path = path()?;
    std::fs::write(&path, format!("{}\n", key.to_openssh()?))
        .with_context(|| format!("cannot write {}", path.display()))?;
    Ok(key)
}

/// Removes the preference. Returns whether a key was preferred.
pub fn clear() -> Result<bool> {
    let path = path()?;
    match std::fs::remove_file(&path) {
        Ok(()) => Ok(true),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(err) => Err(err).with_context(|| format!("cannot remove {}", path.display())),
    }
}

/// Signs `message` with the preferred key through the SSH agent (`ssh-keygen -Y sign -U`).
/// Accepts only a clean exit and a signature made by the preferred key.
pub fn sign(key: &PublicKey, namespace: &str, message: &[u8]) -> Result<String> {
    let mut child = Command::new("ssh-keygen")
        .args(["-Y", "sign", "-n", namespace, "-U", "-f"])
        .arg(path()?)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context("cannot run ssh-keygen")?;
    let mut stdin = child.stdin.take().expect("stdin is piped");
    let output = std::thread::scope(|scope| -> Result<_> {
        // ssh-keygen reads the message only after the agent answers, so a stalled agent must not
        // block the timeout. When ssh-keygen exits before it reads the message, its exit status
        // reports the cause.
        scope.spawn(move || stdin.write_all(message));
        let deadline = Instant::now() + TIMEOUT;
        while child.try_wait()?.is_none() {
            if Instant::now() >= deadline {
                let _ = child.kill();
                let _ = child.wait();
                bail!(
                    "the agent did not sign within {} seconds",
                    TIMEOUT.as_secs()
                );
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        Ok(child.wait_with_output()?)
    })?;
    if !output.status.success() {
        // The last line holds the cause, for example "Signing (stdin) failed: agent refused operation".
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!(
            "{}",
            stderr.trim().lines().last().unwrap_or("ssh-keygen failed")
        );
    }
    let armored = String::from_utf8(output.stdout).context("ssh-keygen returned no signature")?;
    let sshsig = SshSig::from_pem(&armored).context("ssh-keygen returned no signature")?;
    if sshsig.public_key() != key.key_data() {
        bail!("ssh-keygen signed with another key");
    }
    Ok(armored)
}

/// A short name for messages: the key comment, else its fingerprint.
pub fn name(key: &PublicKey) -> String {
    match key.comment() {
        "" => key.fingerprint(HashAlg::Sha256).to_string(),
        comment => comment.to_owned(),
    }
}
