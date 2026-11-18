//! Sign git commits with a non-exportable key in the TPM (Linux) or the Secure Enclave (macOS).
//!
//! git runs this program as `gpg.ssh.program`. `-Y sign` signs with the machine key. Every other
//! `-Y` mode goes to the real ssh-keygen unchanged, so verification works as before.

mod git_setup;
mod key;
mod prefer;
mod sshsig;

use std::ffi::OsString;
use std::process::ExitCode;

const USAGE: &str = "\
Usage:
  machine-signing init [--prefer <public key file> [--title <GitHub title>] | --no-prefer]
      Create the machine key if it does not exist, and configure global git to sign commits with it.
      --prefer signs with that SSH agent key, such as a YubiKey key, whenever the agent can.
      Otherwise the machine key signs. --title names the preferred key on GitHub.
      --no-prefer removes the preference.
  machine-signing -Y <mode> ...
      ssh-keygen compatible. git calls this. -Y sign for the machine key uses the preferred key
      or the machine key. Every other request runs ssh-keygen.";

fn main() -> ExitCode {
    let args: Vec<OsString> = std::env::args_os().skip(1).collect();
    let mode = args
        .iter()
        .position(|arg| arg == "-Y")
        .and_then(|i| args.get(i + 1));
    let result = match (args.first().and_then(|arg| arg.to_str()), mode) {
        (Some("init"), None) => git_setup::init(&args[1..]),
        (_, Some(mode)) if mode == "sign" => sshsig::run(&args),
        (_, Some(_)) => sshsig::exec_ssh_keygen(&args),
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
