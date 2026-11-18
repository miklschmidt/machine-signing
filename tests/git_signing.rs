//! End to end on a software TPM: init, a signed commit that git verifies, and refusal of another key.
#![cfg(target_os = "linux")]

use std::net::{TcpListener, TcpStream};
use std::path::Path;
use std::process::{Child, Command, Output};
use std::time::{Duration, Instant};

struct Swtpm(Child);

impl Drop for Swtpm {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

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

fn start_swtpm(state: &Path) -> (Swtpm, String) {
    let port = free_port_pair();
    let ctrl = port + 1;
    let child = Command::new("swtpm")
        .args(["socket", "--tpm2", "--flags", "not-need-init,startup-clear"])
        .arg("--tpmstate")
        .arg(format!("dir={}", state.display()))
        .args(["--server", &format!("type=tcp,port={port}")])
        .args(["--ctrl", &format!("type=tcp,port={ctrl}")])
        .spawn()
        .expect("swtpm must be on PATH: run the tests in `nix develop`");
    let guard = Swtpm(child);
    let deadline = Instant::now() + Duration::from_secs(10);
    while TcpStream::connect(("127.0.0.1", port)).is_err() {
        assert!(Instant::now() < deadline, "swtpm did not start");
        std::thread::sleep(Duration::from_millis(20));
    }
    (guard, format!("swtpm:host=127.0.0.1,port={port}"))
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

#[test]
fn signs_commits_that_git_verifies() {
    let tmp = tempfile::tempdir().unwrap();
    let state = tmp.path().join("tpm");
    std::fs::create_dir(&state).unwrap();
    let (_swtpm, tcti) = start_swtpm(&state);

    let home = tmp.path().join("home");
    std::fs::create_dir(&home).unwrap();
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
    let mut path = vec![bin.clone()];
    path.extend(std::env::split_paths(&std::env::var_os("PATH").unwrap()));
    let path = std::env::join_paths(path).unwrap();
    let gh_log = tmp.path().join("gh.log");
    let env = |cmd: &mut Command| {
        cmd.env_clear()
            .env("PATH", &path)
            .env("GH_KEYS", tmp.path().join("gh-keys"))
            .env("GH_LOG", &gh_log)
            .env("HOME", &home)
            .env("TCTI", &tcti)
            .env("GIT_CONFIG_NOSYSTEM", "1");
    };
    let tool = || {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_machine-signing"));
        env(&mut cmd);
        cmd
    };
    let git = |dir: &Path, args: &[&str]| {
        let mut cmd = Command::new("git");
        env(&mut cmd);
        cmd.current_dir(dir).args(args);
        cmd
    };

    run(&mut git(
        &home,
        &["config", "--global", "user.email", "dev@example.com"],
    ));
    run(&mut git(&home, &["config", "--global", "user.name", "Dev"]));

    let first = run(tool().arg("init")).stdout;
    let second = run(tool().arg("init")).stdout;
    assert_eq!(first, second, "init must reuse the existing key");
    assert!(String::from_utf8_lossy(&first).starts_with("ecdsa-sha2-nistp256 "));
    let gh_calls = std::fs::read_to_string(&gh_log).unwrap();
    assert_eq!(
        gh_calls.lines().count(),
        1,
        "init must add the key to GitHub once: {gh_calls}"
    );
    assert!(gh_calls.contains("--type signing"), "{gh_calls}");

    let repo = home.join("repo");
    std::fs::create_dir(&repo).unwrap();
    run(&mut git(&repo, &["init", "-q"]));
    run(&mut git(
        &repo,
        &["commit", "-q", "--allow-empty", "-m", "signed"],
    ));
    let verified = run(&mut git(&repo, &["verify-commit", "HEAD"]));
    let stderr = String::from_utf8_lossy(&verified.stderr);
    assert!(
        stderr.contains("Good \"git\" signature for dev@example.com"),
        "{stderr}"
    );

    let other = home.join("other");
    run(Command::new("ssh-keygen")
        .args(["-q", "-t", "ecdsa", "-N", "", "-f"])
        .arg(&other));
    let message = home.join("message");
    std::fs::write(&message, "data").unwrap();
    let refused = tool()
        .args(["-Y", "sign", "-n", "git", "-f"])
        .arg(other.with_extension("pub"))
        .arg(&message)
        .output()
        .unwrap();
    assert!(
        !refused.status.success(),
        "signing for another key must fail"
    );
    assert!(String::from_utf8_lossy(&refused.stderr).contains("is not this machine's key"));
}
