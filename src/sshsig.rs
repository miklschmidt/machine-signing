//! `ssh-keygen -Y sign` compatible signing with the preferred key or the machine key.

use crate::key::Key;
use crate::prefer;
use anyhow::{Context, Result, bail};
use ssh_key::{HashAlg, LineEnding, PublicKey, SshSig};
use std::ffi::OsString;
use std::io::{IsTerminal, Read, Write};
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::Command;

/// Signs each file into `<file>.sig`, or standard input to standard output when no file is given.
/// A request for any key other than the machine key goes to ssh-keygen unchanged.
///
/// Accepts the options that git and jj pass: `-Y sign -n <namespace> -f <public key> [-U] [-O <option>] [file...]`.
pub fn run(all_args: &[OsString]) -> Result<()> {
    let mut namespace = None;
    let mut key_file = None;
    let mut files = Vec::new();
    let mut args = all_args.iter();
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

    let requested = PublicKey::read_openssh_file(&key_file).with_context(|| {
        format!(
            "cannot read an OpenSSH public key from {}",
            key_file.display()
        )
    })?;
    let Some(key) = Key::load_existing()?.filter(|key| requested.key_data() == &key.public) else {
        return exec_ssh_keygen(all_args);
    };
    let preferred = prefer::load()?;
    let sign = |message: &[u8]| sign(&key, preferred.as_ref(), &namespace, message);

    if files.is_empty() {
        let mut message = Vec::new();
        std::io::stdin().read_to_end(&mut message)?;
        std::io::stdout().write_all(sign(&message)?.as_bytes())?;
        return Ok(());
    }
    for file in files {
        let message =
            std::fs::read(&file).with_context(|| format!("cannot read {}", file.display()))?;
        let mut target = file.into_os_string();
        target.push(".sig");
        std::fs::write(&target, sign(&message)?)
            .with_context(|| format!("cannot write {}", target.to_string_lossy()))?;
    }
    Ok(())
}

/// Replaces this process with ssh-keygen and the same arguments.
pub fn exec_ssh_keygen(args: &[OsString]) -> Result<()> {
    let err = Command::new("ssh-keygen").args(args).exec();
    Err(anyhow::Error::new(err).context("cannot run ssh-keygen"))
}

/// Signs with the preferred key when the agent can, else with the machine key.
fn sign(
    key: &Key,
    preferred: Option<&PublicKey>,
    namespace: &str,
    message: &[u8],
) -> Result<String> {
    if let Some(preferred) = preferred {
        match prefer::sign(preferred, namespace, message) {
            Ok(signature) => return Ok(signature),
            Err(err) => notify(&format!(
                "signed with the machine key, because the agent could not sign with {}: {err:#}. \
                 If the YubiKey was unplugged since ssh-add, run ssh-add -e and ssh-add -s with its PKCS#11 provider",
                prefer::name(preferred)
            )),
        }
    }
    sign_with_machine_key(key, namespace, message)
}

/// Tells the person at the terminal. git hides the stderr of a signing program that succeeds.
fn notify(message: &str) {
    eprintln!("machine-signing: {message}");
    if !std::io::stderr().is_terminal()
        && let Ok(mut tty) = std::fs::OpenOptions::new().write(true).open("/dev/tty")
    {
        let _ = writeln!(tty, "machine-signing: {message}");
    }
}

/// Returns the armored SSHSIG of `message`, with the sha512 message hash that ssh-keygen uses.
fn sign_with_machine_key(key: &Key, namespace: &str, message: &[u8]) -> Result<String> {
    let signed_data = SshSig::signed_data(namespace, HashAlg::Sha512, message)?;
    let signature = key.sign(&signed_data)?.try_into()?;
    let sshsig = SshSig::new(key.public.clone(), namespace, HashAlg::Sha512, signature)?;
    Ok(sshsig.to_pem(LineEnding::LF)?)
}
