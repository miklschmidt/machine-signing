<img src="assets/icon.svg" width="64" height="64" alt="">

# machine-signing

machine-signing signs your git commits with a key that cannot leave this machine.
The key lives in the TPM on Linux, or in the Secure Enclave on macOS 27 or later on Apple silicon.
git signs through its SSH signing support, so you do not need GPG.

The key is ECDSA P-256 (`ecdsa-sha2-nistp256`), because the Secure Enclave supports only that curve.
GitHub and GitLab accept this key type for signing.

## Install

On Linux, you need the tpm2-tss libraries and access to `/dev/tpmrm0`.
On macOS, you need the Xcode Command Line Tools, because the build compiles a small Swift file.

```sh
cargo install --path .
```

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
4. It adds the key for your `user.email` to the allowed signers file, so that `git log --show-signature` can verify your commits.
5. It sets `gpg.format=ssh`, `gpg.ssh.program=machine-signing`, `user.signingkey` and `commit.gpgsign=true` in your global git configuration. It prints each value that it changes.

To add signing keys, `gh` needs the `admin:ssh_signing_key` scope. To give `gh` that scope, run:

```sh
gh auth refresh -h github.com -s admin:ssh_signing_key
```

If `gh` is not on your PATH, or `gh` cannot add the key, `init` prints the `gh ssh-key add` command for you to run.

If git cannot write your global configuration, `init` prints the configuration for you to add yourself.
For example, git cannot write a `~/.config/git/config` that home-manager manages.

You can run `init` again at any time. It does not replace the key.

## How it works

git runs `machine-signing` as its SSH signing program (`gpg.ssh.program`).
For `-Y sign`, machine-signing makes sure that the requested key is the machine key, and the hardware signs the commit.
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

The test starts a software TPM, runs `init`, makes a signed commit, and makes sure that `git verify-commit` accepts it.
The test does not touch your git configuration or your TPM.

The architecture is in the archboard vault in `.archboard/vault`.
