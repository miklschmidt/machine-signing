//! `ssh-keygen -Y sign` compatible signing with the machine key.

use crate::key::Key;
use anyhow::{Context, Result, bail};
use ssh_key::{HashAlg, LineEnding, PublicKey, SshSig};
use std::ffi::OsString;
use std::io::{Read, Write};
use std::path::PathBuf;

/// Signs each file into `<file>.sig`, or standard input to standard output when no file is given.
///
/// Accepts the options that git and jj pass: `-Y sign -n <namespace> -f <public key> [-U] [-O <option>] [file...]`.
pub fn run(args: &[OsString]) -> Result<()> {
    let mut namespace = None;
    let mut key_file = None;
    let mut files = Vec::new();
    let mut args = args.iter();
    while let Some(arg) = args.next() {
        let text = arg.to_string_lossy();
        // Options take their value attached (`-ngit`) or as the next argument (`-n git`).
        let (flag, attached) = match text.get(..2) {
            Some(flag) if flag.starts_with('-') => (flag, &text[2..]),
            _ => ("", ""),
        };
        let mut value = || -> Result<OsString> {
            match attached {
                "" => args
                    .next()
                    .cloned()
                    .with_context(|| format!("{flag} needs a value")),
                attached => Ok(attached.into()),
            }
        };
        match flag {
            "-Y" | "-O" => drop(value()?),
            "-n" => namespace = Some(value()?.to_string_lossy().into_owned()),
            "-f" => key_file = Some(PathBuf::from(value()?)),
            "-U" if attached.is_empty() => {}
            // `-` means standard input, the same as no file.
            _ if text == "-" => {}
            _ if text.starts_with('-') => {
                bail!("unsupported option for -Y sign: {text}")
            }
            _ => files.push(PathBuf::from(arg)),
        }
    }
    let namespace = namespace.context("-Y sign needs -n <namespace>")?;
    let key_file = key_file.context("-Y sign needs -f <public key file>")?;

    let key = Key::load()?;
    let requested = PublicKey::read_openssh_file(&key_file).with_context(|| {
        format!(
            "cannot read an OpenSSH public key from {}",
            key_file.display()
        )
    })?;
    if requested.key_data() != &key.public {
        bail!(
            "{} is not this machine's key. Set user.signingkey with `machine-signing init`",
            key_file.display()
        );
    }

    if files.is_empty() {
        let mut message = Vec::new();
        std::io::stdin().read_to_end(&mut message)?;
        std::io::stdout().write_all(sign(&key, &namespace, &message)?.as_bytes())?;
        return Ok(());
    }
    for file in files {
        let message =
            std::fs::read(&file).with_context(|| format!("cannot read {}", file.display()))?;
        let mut target = file.into_os_string();
        target.push(".sig");
        std::fs::write(&target, sign(&key, &namespace, &message)?)
            .with_context(|| format!("cannot write {}", target.to_string_lossy()))?;
    }
    Ok(())
}

/// Returns the armored SSHSIG of `message`, with the sha512 message hash that ssh-keygen uses.
fn sign(key: &Key, namespace: &str, message: &[u8]) -> Result<String> {
    let signed_data = SshSig::signed_data(namespace, HashAlg::Sha512, message)?;
    let signature = key.sign(&signed_data)?.try_into()?;
    let sshsig = SshSig::new(key.public.clone(), namespace, HashAlg::Sha512, signature)?;
    Ok(sshsig.to_pem(LineEnding::LF)?)
}
