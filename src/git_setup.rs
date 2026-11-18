//! `machine-signing init`: create the key if needed and configure global git to sign with it.

use crate::key::{HARDWARE, Key, Loaded};
use crate::prefer;
use anyhow::{Context, Result, bail};
use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};
use std::process::Command;

const DEFAULT_ALLOWED_SIGNERS: &str = "~/.config/git/allowed_signers";

const USAGE: &str = "usage: machine-signing init [--prefer <public key file> [--title <GitHub title>] | --no-prefer]";

enum Preference {
    Keep,
    Set {
        file: PathBuf,
        title: Option<String>,
    },
    Clear,
}

fn parse(args: &[OsString]) -> Result<Preference> {
    let (mut file, mut title, mut clear) = (None, None, false);
    let mut args = args.iter();
    while let Some(arg) = args.next() {
        let mut value = |flag: &str| args.next().with_context(|| format!("{flag} needs a value"));
        match arg.to_str() {
            Some("--prefer") => file = Some(PathBuf::from(value("--prefer")?)),
            Some("--title") => title = Some(value("--title")?.to_string_lossy().into_owned()),
            Some("--no-prefer") => clear = true,
            _ => bail!("{USAGE}"),
        }
    }
    Ok(match (file, title, clear) {
        (None, None, false) => Preference::Keep,
        (Some(file), title, false) => Preference::Set { file, title },
        (None, None, true) => Preference::Clear,
        (None, Some(_), false) => {
            bail!("--title names the preferred key on GitHub, so it needs --prefer")
        }
        _ => bail!("{USAGE}"),
    })
}

pub fn init(args: &[OsString]) -> Result<()> {
    let preference = parse(args)?;
    let key = match Key::load_or_create()? {
        Loaded::Created(key) => {
            eprintln!("Created a new {HARDWARE} key: {}", Key::path()?.display());
            key
        }
        Loaded::Existing(key) => {
            eprintln!(
                "Using the existing {HARDWARE} key: {}",
                Key::path()?.display()
            );
            key
        }
    };
    let host = hostname();
    let public = ssh_key::PublicKey::new(key.public.clone(), format!("machine-signing@{host}"));
    let public_line = public.to_openssh()?;
    let public_path = Key::public_path()?;
    std::fs::write(&public_path, format!("{public_line}\n"))
        .with_context(|| format!("cannot write {}", public_path.display()))?;

    eprintln!("Public key:");
    println!("{public_line}");
    eprintln!();
    add_to_github(&public, &public_path, &format!("{host} {HARDWARE}"));
    let allowed_signers = add_allowed_signer(&public)?;

    let mut title = None;
    let preferred = match preference {
        Preference::Keep => prefer::load()?,
        Preference::Set {
            file,
            title: chosen,
        } => {
            title = chosen;
            Some(prefer::set(&file, &key)?)
        }
        Preference::Clear => {
            if prefer::clear()? {
                eprintln!("\nRemoved the preferred key. The machine key signs all commits.");
            }
            None
        }
    };
    if let Some(preferred) = preferred {
        let name = prefer::name(&preferred);
        eprintln!("\nPreferred key: {}", preferred.to_openssh()?);
        match prefer::sign(&preferred, "git", b"machine-signing init test") {
            Ok(_) => eprintln!("The SSH agent signs with {name}, so it signs your commits."),
            Err(err) => eprintln!(
                "The SSH agent cannot sign with {name} now, so the machine key signs instead: {err:#}"
            ),
        }
        add_to_github(
            &preferred,
            &prefer::path()?,
            &title.unwrap_or_else(|| format!("{name} via {host} agent")),
        );
        add_allowed_signer(&preferred)?;
    }
    eprintln!();

    let mut settings = vec![
        ("gpg.format", "ssh".to_owned()),
        ("gpg.ssh.program", program()?),
        (
            "user.signingkey",
            public_path.to_string_lossy().into_owned(),
        ),
        ("commit.gpgsign", "true".to_owned()),
    ];
    if let Some(path) = allowed_signers {
        settings.insert(2, ("gpg.ssh.allowedSignersFile", path));
    }
    for (name, value) in &settings {
        if let Err(err) = set(name, value) {
            eprintln!(
                "\nAdd these settings to your git configuration:\n\n{}",
                gitconfig(&settings)
            );
            return Err(err.context("cannot write the global git configuration"));
        }
    }

    Ok(())
}

/// Sets a global git value and reports the change. An equal value is left alone.
fn set(name: &str, value: &str) -> Result<()> {
    let old = get(name, false)?;
    if old.as_deref() == Some(value) {
        eprintln!("git {name} is already {value}");
        return Ok(());
    }
    git(&["config", "--global", name, value])?;
    match old {
        Some(old) => eprintln!("git {name}: {old} -> {value}"),
        None => eprintln!("git {name}: {value}"),
    }
    Ok(())
}

/// Appends the key to the allowed signers file. Returns the allowedSignersFile value to set when git has none.
fn add_allowed_signer(public: &ssh_key::PublicKey) -> Result<Option<String>> {
    let Some(email) = get("user.email", false)? else {
        eprintln!(
            "git user.email is not set, so no allowed signers entry was written. Set it and run init again."
        );
        return Ok(None);
    };
    let (path, setting) = match get("gpg.ssh.allowedSignersFile", true)? {
        Some(path) => (PathBuf::from(path), None),
        None => {
            let home =
                dirs::home_dir().context("cannot find the home directory: HOME is not set")?;
            (
                home.join(".config/git/allowed_signers"),
                Some(DEFAULT_ALLOWED_SIGNERS.to_owned()),
            )
        }
    };
    let mut key = public.clone();
    key.set_comment("");
    let entry = format!("{email} namespaces=\"git\" {}", key.to_openssh()?);
    match append_line(&path, &entry) {
        Ok(true) => eprintln!("{}: allowed this key for {email}", path.display()),
        Ok(false) => eprintln!("{} already allows this key for {email}", path.display()),
        Err(err) => {
            eprintln!(
                "\nAdd this line to {} and run init again:\n  {entry}",
                path.display()
            );
            return Err(err).with_context(|| format!("cannot update {}", path.display()));
        }
    }
    Ok(setting)
}

/// Appends `line` to the file unless the file has it already. Returns whether it appended.
fn append_line(path: &Path, line: &str) -> std::io::Result<bool> {
    let existing = match std::fs::read_to_string(path) {
        Ok(text) => text,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(err) => return Err(err),
    };
    if existing.lines().any(|existing| existing.trim() == line) {
        return Ok(false);
    }
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let separator = if existing.is_empty() || existing.ends_with('\n') {
        ""
    } else {
        "\n"
    };
    std::fs::write(path, format!("{existing}{separator}{line}\n"))?;
    Ok(true)
}

/// Renders settings as git configuration file text, for configurations that git cannot write.
fn gitconfig(settings: &[(&str, String)]) -> String {
    let mut text = String::new();
    for (name, value) in settings {
        let (section, key) = name.rsplit_once('.').expect("setting names have a section");
        let header = match section.split_once('.') {
            Some((section, sub)) => format!("[{section} \"{sub}\"]"),
            None => format!("[{section}]"),
        };
        let value = value.replace('\\', r"\\").replace('"', r#"\""#);
        text.push_str(&format!("{header}\n\t{key} = \"{value}\"\n"));
    }
    text
}

/// Adds the key to GitHub as a signing key through gh, when gh is on PATH and GitHub does not have the key yet.
/// A failure here leaves the local setup intact, so it prints what to do instead of failing init.
fn add_to_github(public: &ssh_key::PublicKey, public_path: &Path, title: &str) {
    let manual = format!(
        "gh ssh-key add {} --type signing --title {}",
        shell_quote(&public_path.to_string_lossy()),
        shell_quote(title)
    );
    if find_on_path(OsStr::new("gh")).is_none() {
        eprintln!("Add the key to GitHub as a signing key:\n  {manual}");
        return;
    }
    let listed = Command::new("gh")
        .args([
            "api",
            "user/ssh_signing_keys",
            "--paginate",
            "--jq",
            ".[].key",
        ])
        .output();
    if let Ok(listed) = listed
        && listed.status.success()
        && String::from_utf8_lossy(&listed.stdout)
            .lines()
            .filter_map(|line| ssh_key::PublicKey::from_openssh(line).ok())
            .any(|key| key.key_data() == public.key_data())
    {
        eprintln!("GitHub already has this signing key");
        return;
    }
    let added = Command::new("gh")
        .args(["ssh-key", "add"])
        .arg(public_path)
        .args(["--type", "signing", "--title", title])
        .output();
    match added {
        Ok(out) if out.status.success() => {
            eprintln!("Added the key to GitHub as the signing key {title}")
        }
        Ok(out) => eprintln!(
            "gh could not add the key to GitHub: {}\n\
             If gh needs the permission, run:\n  gh auth refresh -h github.com -s admin:ssh_signing_key\n\
             Then run machine-signing init again, or add the key yourself:\n  {manual}",
            String::from_utf8_lossy(&out.stderr).trim()
        ),
        Err(err) => eprintln!("cannot run gh: {err}\nAdd the key yourself:\n  {manual}"),
    }
}

/// Quotes `arg` for a POSIX shell, so a printed command works for a title such as `Kim's YubiKey`.
fn shell_quote(arg: &str) -> String {
    format!("'{}'", arg.replace('\'', r"'\''"))
}

/// The value git runs as gpg.ssh.program: the bare name when PATH finds this executable, else its absolute path.
fn program() -> Result<String> {
    let exe = std::env::current_exe()?.canonicalize()?;
    let name = exe.file_name().context("the executable has no file name")?;
    Ok(if find_on_path(name) == Some(exe.clone()) {
        name.to_string_lossy().into_owned()
    } else {
        exe.to_string_lossy().into_owned()
    })
}

/// The canonical path of the first executable called `name` on PATH.
fn find_on_path(name: &OsStr) -> Option<PathBuf> {
    std::env::split_paths(&std::env::var_os("PATH")?).find_map(|dir| {
        dir.join(name)
            .canonicalize()
            .ok()
            .filter(|found| is_executable(found))
    })
}

fn is_executable(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    path.metadata()
        .is_ok_and(|meta| meta.is_file() && meta.permissions().mode() & 0o111 != 0)
}

fn get(name: &str, as_path: bool) -> Result<Option<String>> {
    let mut args = vec!["config", "--global", "--includes", "--get"];
    if as_path {
        args.push("--type=path");
    }
    args.push(name);
    let output = Command::new("git")
        .args(&args)
        .output()
        .context("cannot run git")?;
    match output.status.code() {
        Some(0) => Ok(Some(
            String::from_utf8(output.stdout)?.trim_end().to_owned(),
        )),
        Some(1) => Ok(None),
        _ => bail!(
            "git config --get {name} failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ),
    }
}

fn git(args: &[&str]) -> Result<()> {
    let output = Command::new("git")
        .args(args)
        .output()
        .context("cannot run git")?;
    if !output.status.success() {
        bail!(
            "git {} failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(())
}

/// The short host name. `uname -n` exists on every Linux and macOS, unlike `hostname -s`.
fn hostname() -> String {
    Command::new("uname")
        .arg("-n")
        .output()
        .ok()
        .and_then(|out| String::from_utf8(out.stdout).ok())
        .and_then(|name| name.trim().split('.').next().map(str::to_owned))
        .filter(|name| !name.is_empty())
        .unwrap_or_else(|| "this-machine".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn printed_gh_command_keeps_quotes_in_the_title() {
        let title = "Kim's YubiKey via host agent";
        let out = Command::new("sh")
            .args(["-c", &format!("printf %s {}", shell_quote(title))])
            .output()
            .unwrap();
        assert_eq!(String::from_utf8(out.stdout).unwrap(), title);
    }

    #[test]
    fn printed_gitconfig_reads_back_the_same_values() {
        let path = r#"/home/a "b"\c/key.pub"#;
        let file = tempfile::NamedTempFile::new().unwrap();
        let settings = [
            ("user.signingkey", path.to_owned()),
            ("gpg.ssh.program", "machine-signing".to_owned()),
        ];
        std::fs::write(file.path(), gitconfig(&settings)).unwrap();
        for (name, value) in settings {
            let out = Command::new("git")
                .args(["config", "--file"])
                .arg(file.path())
                .args(["--get", name])
                .output()
                .unwrap();
            assert_eq!(String::from_utf8(out.stdout).unwrap().trim_end(), value);
        }
    }

    #[test]
    fn allowed_signers_file_that_cannot_be_read_is_left_alone() {
        let file = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(file.path(), b"caf\xe9@example.com ssh-ed25519 AAAA\n").unwrap();
        assert!(append_line(file.path(), "me@example.com namespaces=\"git\" key").is_err());
        assert_eq!(
            std::fs::read(file.path()).unwrap(),
            b"caf\xe9@example.com ssh-ed25519 AAAA\n"
        );
    }
}
