//! Sign git commits with a non-exportable key in the TPM (Linux) or the Secure Enclave (macOS).
//!
//! git runs this program as `gpg.ssh.program`. `-Y sign` signs with the machine key. Every other
//! `-Y` mode goes to the real ssh-keygen unchanged, so verification works as before.

mod git_setup;
mod key;
mod sshsig;

use std::ffi::OsString;
use std::os::unix::process::CommandExt;
use std::process::{Command, ExitCode};

const USAGE: &str = "\
Usage:
  machine-signing init
      Create the machine key if it does not exist, and configure global git to sign commits with it.
  machine-signing -Y <mode> ...
      ssh-keygen compatible. git calls this. -Y sign uses the machine key; other modes run ssh-keygen.";

fn main() -> ExitCode {
    let args: Vec<OsString> = std::env::args_os().skip(1).collect();
    let mode = args
        .iter()
        .position(|arg| arg == "-Y")
        .and_then(|i| args.get(i + 1));
    let result = match (args.first().and_then(|arg| arg.to_str()), mode) {
        (Some("init"), None) if args.len() == 1 => git_setup::init(),
        (_, Some(mode)) if mode == "sign" => sshsig::run(&args),
        (_, Some(_)) => {
            let err = Command::new("ssh-keygen").args(&args).exec();
            Err(anyhow::Error::new(err).context("cannot run ssh-keygen"))
        }
        _ => {
            eprintln!("{USAGE}");
            return ExitCode::from(2);
        }
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("machine-signing: {err:#}");
            ExitCode::FAILURE
        }
    }
}
