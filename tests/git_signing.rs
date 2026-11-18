//! End to end on a software TPM, with a fake gh and a real ssh-agent: init, signed commits that
//! git verifies, the preferred agent key with fallback, and passthrough of other keys.
#![cfg(target_os = "linux")]

use std::ffi::{OsStr, OsString};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Child, Command, Output};
use std::sync::{Mutex, PoisonError};
use std::time::{Duration, Instant};

struct Killed(Child);

impl Drop for Killed {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// Held from the choice of ports until swtpm listens on them, so parallel tests never pick the same ports.
static SWTPM_START: Mutex<()> = Mutex::new(());

/// A free port whose successor is also free: the swtpm TCTI expects the control port at port + 1.
fn free_port_pair() -> u16 {
    loop {
        let port = TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        if port < u16::MAX && TcpListener::bind(("127.0.0.1", port + 1)).is_ok() {
            return port;
        }
    }
}

fn wait_for(what: &str, ready: impl Fn() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while !ready() {
        assert!(Instant::now() < deadline, "{what} did not start");
        std::thread::sleep(Duration::from_millis(20));
    }
}

fn run(cmd: &mut Command) -> Output {
    let output = cmd.output().unwrap();
    assert!(
        output.status.success(),
        "{cmd:?} failed\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    output
}

/// A home directory with a software TPM, a fake gh, git user settings and an empty repository.
struct Machine {
    _swtpm: Killed,
    tcti: String,
    home: PathBuf,
    repo: PathBuf,
    path: OsString,
    gh_keys: PathBuf,
    gh_log: PathBuf,
    agent: Option<PathBuf>,
    _tmp: tempfile::TempDir,
}

impl Machine {
    fn new() -> Machine {
        let tmp = tempfile::tempdir().unwrap();
        let state = tmp.path().join("tpm");
        std::fs::create_dir(&state).unwrap();
        let starting = SWTPM_START.lock().unwrap_or_else(PoisonError::into_inner);
        let port = free_port_pair();
        let swtpm = Killed(
            Command::new("swtpm")
                .args(["socket", "--tpm2", "--flags", "not-need-init,startup-clear"])
                .arg("--tpmstate")
                .arg(format!("dir={}", state.display()))
                .args(["--server", &format!("type=tcp,port={port}")])
                .args(["--ctrl", &format!("type=tcp,port={}", port + 1)])
                .spawn()
                .expect("swtpm must be on PATH: run the tests in `nix develop`"),
        );
        wait_for("swtpm", || TcpStream::connect(("127.0.0.1", port)).is_ok());
        drop(starting);

        // A fake gh before the real one on PATH: it lists the keys it was given, and logs each add.
        let bin = tmp.path().join("bin");
        std::fs::create_dir(&bin).unwrap();
        let gh = bin.join("gh");
        std::fs::write(
            &gh,
            "#!/bin/sh\ncase \"$1\" in\n  api) cat \"$GH_KEYS\" 2>/dev/null ;;\n  \
             ssh-key) cut -d' ' -f1,2 \"$3\" >> \"$GH_KEYS\"; echo \"$@\" >> \"$GH_LOG\" ;;\nesac\n",
        )
        .unwrap();
        std::fs::set_permissions(&gh, std::os::unix::fs::PermissionsExt::from_mode(0o755)).unwrap();
        let mut path = vec![bin];
        path.extend(std::env::split_paths(&std::env::var_os("PATH").unwrap()));

        let home = tmp.path().join("home");
        let repo = home.join("repo");
        std::fs::create_dir_all(&repo).unwrap();
        let machine = Machine {
            _swtpm: swtpm,
            tcti: format!("swtpm:host=127.0.0.1,port={port}"),
            path: std::env::join_paths(path).unwrap(),
            gh_keys: tmp.path().join("gh-keys"),
            gh_log: tmp.path().join("gh.log"),
            home,
            repo,
            agent: None,
            _tmp: tmp,
        };
        run(&mut machine.git(&["config", "--global", "user.email", "dev@example.com"]));
        run(&mut machine.git(&["config", "--global", "user.name", "Dev"]));
        run(&mut machine.git(&["init", "-q"]));
        machine
    }

    fn command(&self, program: impl AsRef<OsStr>) -> Command {
        let mut cmd = Command::new(program);
        cmd.env_clear()
            .env("PATH", &self.path)
            .env("HOME", &self.home)
            .env("TCTI", &self.tcti)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GH_KEYS", &self.gh_keys)
            .env("GH_LOG", &self.gh_log)
            .current_dir(&self.repo);
        if let Some(agent) = &self.agent {
            cmd.env("SSH_AUTH_SOCK", agent);
        }
        cmd
    }

    fn tool(&self, args: &[impl AsRef<OsStr>]) -> Command {
        let mut cmd = self.command(env!("CARGO_BIN_EXE_machine-signing"));
        cmd.args(args);
        cmd
    }

    fn git(&self, args: &[&str]) -> Command {
        let mut cmd = self.command("git");
        cmd.args(args);
        cmd
    }

    /// Makes a signed commit and returns git's verification report.
    fn signed_commit(&self) -> String {
        run(&mut self.git(&["commit", "-q", "--allow-empty", "-m", "signed"]));
        let verified = run(&mut self.git(&["verify-commit", "HEAD"]));
        String::from_utf8(verified.stderr).unwrap()
    }

    /// Makes an ECDSA key without a passphrase. Returns its private key path and SHA256 fingerprint.
    fn ssh_key(&self, name: &str) -> (PathBuf, String) {
        let private = self.home.join(name);
        run(Command::new("ssh-keygen")
            .args(["-q", "-t", "ecdsa", "-N", "", "-C", name, "-f"])
            .arg(&private));
        let listed = run(Command::new("ssh-keygen").arg("-lf").arg(&private)).stdout;
        let listed = String::from_utf8(listed).unwrap();
        (private, listed.split(' ').nth(1).unwrap().to_owned())
    }

    fn gh_calls(&self) -> String {
        std::fs::read_to_string(&self.gh_log).unwrap()
    }
}

#[test]
fn signs_commits_that_git_verifies() {
    let machine = Machine::new();

    let first = run(&mut machine.tool(&["init"])).stdout;
    // An empty PATH entry finds the binary only from its own directory, so gpg.ssh.program must
    // not be the bare name, or git cannot run it in the repository.
    let exe = std::path::Path::new(env!("CARGO_BIN_EXE_machine-signing"));
    let mut path = machine.path.clone();
    path.push(":");
    let mut init = machine.tool(&["init"]);
    init.env("PATH", path).current_dir(exe.parent().unwrap());
    let second = run(&mut init).stdout;
    assert_eq!(first, second, "init must reuse the existing key");
    assert!(String::from_utf8_lossy(&first).starts_with("ecdsa-sha2-nistp256 "));
    let gh_calls = machine.gh_calls();
    assert_eq!(
        gh_calls.lines().count(),
        1,
        "init must add the key once: {gh_calls}"
    );
    assert!(gh_calls.contains("--type signing"), "{gh_calls}");
    assert!(gh_calls.trim_end().ends_with(" TPM"), "{gh_calls}");

    let report = machine.signed_commit();
    assert!(
        report.contains("Good \"git\" signature for dev@example.com with ECDSA"),
        "{report}"
    );

    // A request for another key goes to ssh-keygen unchanged. git allows user.signingkey to name
    // the public key file or the private key file.
    let (other, _) = machine.ssh_key("other");
    let message = machine.home.join("message");
    std::fs::write(&message, "data").unwrap();
    for key in [other.with_extension("pub"), other] {
        let mut sign = machine.tool(&["-Y", "sign", "-n", "git", "-f"]);
        run(sign.arg(key).arg(&message));
        std::fs::remove_file(machine.home.join("message.sig")).unwrap();
    }
}

#[test]
fn prefers_the_agent_key_and_falls_back_to_the_machine_key() {
    let mut machine = Machine::new();
    let (yubikey, yubikey_fingerprint) = machine.ssh_key("yubikey");

    let socket = machine.home.join("agent.sock");
    let agent = Killed(
        Command::new("ssh-agent")
            .arg("-D")
            .arg("-a")
            .arg(&socket)
            .stdout(std::process::Stdio::null())
            .spawn()
            .unwrap(),
    );
    wait_for("ssh-agent", || socket.exists());
    machine.agent = Some(socket);
    run(machine.command("ssh-add").arg("-q").arg(&yubikey));

    let prefer = [
        OsString::from("init"),
        "--prefer".into(),
        yubikey.with_extension("pub").into(),
        "--title".into(),
        "Test YubiKey".into(),
    ];
    let init = run(&mut machine.tool(&prefer));
    let init_report = String::from_utf8_lossy(&init.stderr);
    assert!(
        init_report.contains("The SSH agent signs with yubikey"),
        "{init_report}"
    );
    assert!(machine.gh_calls().contains("--title Test YubiKey"));

    let report = machine.signed_commit();
    assert!(
        report.contains(&yubikey_fingerprint),
        "the agent key must sign: {report}"
    );

    drop(agent);
    let report = machine.signed_commit();
    assert!(report.contains("with ECDSA key"), "{report}");
    assert!(
        !report.contains(&yubikey_fingerprint),
        "the machine key must sign: {report}"
    );

    run(&mut machine.tool(&["init", "--no-prefer"]));
    assert!(
        !machine
            .home
            .join(".local/share/machine-signing/prefer.pub")
            .exists()
    );
}
