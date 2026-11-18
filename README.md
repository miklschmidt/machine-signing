<img src="assets/icon.svg" width="64" height="64" alt="">

# machine-signing

machine-signing signs your git commits with a key that cannot leave this machine.
The key lives in the TPM on Linux, or in the Secure Enclave on macOS 27 or later on Apple silicon.
git signs through its SSH signing support, so you do not need GPG.

The key is ECDSA P-256 (`ecdsa-sha2-nistp256`), because the Secure Enclave supports only that curve.
GitHub and GitLab accept this key type for signing.

## Install

Each [release](https://github.com/miklschmidt/machine-signing/releases) has a binary for these platforms:

| Platform | Archive |
| --- | --- |
| Linux x86_64 | `machine-signing-v<version>-x86_64-unknown-linux-gnu.tar.gz` |
| Linux arm64 | `machine-signing-v<version>-aarch64-unknown-linux-gnu.tar.gz` |
| macOS on Apple silicon | `machine-signing-v<version>-aarch64-apple-darwin.tar.gz` |

Put `machine-signing` from the archive in a directory on your PATH.
The Linux binaries need the tpm2-tss libraries. On Debian and Ubuntu, `sudo apt install libtss2-dev` installs all of them.
GitHub Actions builds the Linux binaries on Ubuntu 24.04, so they need glibc 2.39 or later.

The macOS binary is not signed with an Apple Developer ID.
If you download it with a browser, macOS blocks it.
To allow it, run `xattr -d com.apple.quarantine machine-signing`.

On NixOS or with Nix on Linux, install the flake package:

```sh
nix profile install github:miklschmidt/machine-signing
```

To build from source, run `cargo install --path .` in a clone.
On Linux, the build needs `pkg-config` and the tpm2-tss development files.
On macOS, the build needs the Xcode Command Line Tools, because it compiles a small Swift file.

On Linux, machine-signing needs access to `/dev/tpmrm0`.

If `init` cannot open `/dev/tpmrm0` on Linux, add your user to the `tss` group and log in again:

```sh
sudo usermod -aG tss $USER
```

## Set up

Run `init` once on each machine:

```sh
machine-signing init
```

`init` does these steps:

1. If no key exists, it creates the key in the hardware. It keeps an existing key.
2. It writes the public key to `key.pub` beside the key file, and prints it.
3. If `gh` is on your PATH, it adds the key to your GitHub account as a signing key. When GitHub already has the key, it skips this step.
4. It adds the key for your `user.email` to the allowed signers file, so that `git log --show-signature` can verify your commits. If `user.email` is not set, it skips this step. Set it and run `init` again.
5. It sets `gpg.format=ssh`, `gpg.ssh.program`, `user.signingkey` and `commit.gpgsign=true` in your global git configuration. If `gpg.ssh.allowedSignersFile` is not set, it sets it to `~/.config/git/allowed_signers`. It prints each value that it changes.

To add signing keys, `gh` needs the `admin:ssh_signing_key` scope. To give `gh` that scope, run:

```sh
gh auth refresh -h github.com -s admin:ssh_signing_key
```

If `gh` is not on your PATH, or `gh` cannot add the key, `init` prints the `gh ssh-key add` command for you to run.

If your PATH finds this `machine-signing`, `gpg.ssh.program` is `machine-signing`. Otherwise it is the full path of the binary.

If git cannot write your global configuration, `init` prints the configuration for you to add yourself.
For example, git cannot write a `~/.config/git/config` that home-manager manages.
If `init` cannot write the allowed signers file, it prints the line for you to add.

You can run `init` again at any time. It does not replace the key.

On GitHub, `init` names the machine key `<host> TPM` on Linux, or `<host> Secure Enclave` on macOS.

## Prefer a YubiKey or another agent key

You can tell machine-signing to sign with a key in your SSH agent, such as a YubiKey PIV key.
When the agent cannot sign with that key, the machine key signs instead.
For example, the agent cannot sign with a YubiKey that is not connected.

1. Write the public key of the agent key to a file, for example with `ssh-add -L > yubikey.pub`. Keep only the line of that key.
2. Run `init` with that file:

   ```sh
   machine-signing init --prefer yubikey.pub
   ```

`init` copies the key to `prefer.pub` beside the machine key and signs a test message through the agent.
It reports whether the agent can sign with the key now.
It also adds the key to GitHub and to the allowed signers file, the same as the machine key.
On GitHub, the key is named `<key comment> via <host> agent`.
If the key has no comment, the name starts with the key fingerprint instead.
To use another name, add `--title <name>` to the `init --prefer` command.

When the machine key signs instead of the preferred key, machine-signing writes one line to your terminal with the cause.

If the YubiKey was unplugged after you loaded it with `ssh-add -s`, the agent refuses to sign with it.
To load it again, run these commands with the PKCS#11 library of your agent:

```sh
ssh-add -e /path/to/opensc-pkcs11.so
ssh-add -s /path/to/opensc-pkcs11.so
```

To sign with the machine key only, run `machine-signing init --no-prefer`.

If git asks for a key that is not the machine key, machine-signing passes the request to `ssh-keygen` unchanged.
For example, a repository can set its own `user.signingkey`.

## How it works

git runs `machine-signing` as its SSH signing program (`gpg.ssh.program`).
For `-Y sign` with the machine key, the preferred key signs through the agent, or else the hardware signs the commit.
machine-signing passes every other `-Y` mode to `ssh-keygen` unchanged, so verification works as before.
No agent or background process runs.

The key file holds the key in a form that only this machine's hardware can use:

| Platform | Key file | Contents |
| --- | --- | --- |
| Linux | `~/.local/share/machine-signing/key` | The TPM public area and the TPM-encrypted private area of a key under the owner storage primary key |
| macOS | `~/Library/Application Support/machine-signing/key` | The CryptoKit `dataRepresentation` of a Secure Enclave key |

A copy of the key file is useless on another machine.
If you clear the TPM, or reset the Mac, the key is gone. Run `init` again to make a new key, and add it to GitHub again.

On Linux, set `TPM2TOOLS_TCTI` or `TCTI` to use another TPM, for example a software TPM.

## Development

The Nix shell has the Rust toolchain, tpm2-tss and swtpm:

```sh
nix develop
cargo test
```

The tests start a software TPM and an SSH agent, and put a fake `gh` first on the PATH.
They run `init`, make signed commits, and make sure that `git verify-commit` accepts them.
The tests do not touch your git configuration, your TPM or your GitHub account.

To make a release, merge the release pull request that release-please opens on `main`.
release-please sets the version and writes the changelog from the Conventional Commits messages.
GitHub Actions then builds the binaries and adds them to the release.
CI does not run on the release pull request, because the workflow token opens it. That pull request changes only the version and the changelog.

The architecture is in the archboard vault in `.archboard/vault`.
