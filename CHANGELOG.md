# Changelog

## 0.1.0 (2026-11-18)


### Features

* add the key to GitHub as a signing key during init when gh is on PATH ([d1e2b08](https://github.com/miklschmidt/machine-signing/commit/d1e2b084d327d51ddeb73d7357a33abd9ec1507f))
* **init:** add --touch-id and name the Mac by its LocalHostName ([#2](https://github.com/miklschmidt/machine-signing/issues/2)) ([8892cfa](https://github.com/miklschmidt/machine-signing/commit/8892cfaeaba02ab1c5c3694d6d98f6e7e80afe31))
* prefer an SSH agent key such as a YubiKey, with machine key fallback ([27ccc20](https://github.com/miklschmidt/machine-signing/commit/27ccc20040cc80f342212ccd8b4f58f579987abc))
* sign git commits with a TPM or Secure Enclave key through SSH signing ([1910ae1](https://github.com/miklschmidt/machine-signing/commit/1910ae1b8ebf380d19068404f8150ff14583c172))


### Bug Fixes

* **build:** link the Swift back-deployment libraries on macOS ([e0b3ddf](https://github.com/miklschmidt/machine-signing/commit/e0b3ddffad49e4a1a6f92920cff8a969cb273417))
* **build:** rerun the build script only when build.rs changes ([6a5aa87](https://github.com/miklschmidt/machine-signing/commit/6a5aa872dad0938721eda5b0d28a7b2a011b617c))
* **init:** escape quotes and backslashes in the printed gitconfig block ([394327d](https://github.com/miklschmidt/machine-signing/commit/394327d62bacfb7b6fafa0796697a74427b0be7e))
* **init:** keep an unreadable allowed signers file and print the entry when it cannot be written ([2013a0b](https://github.com/miklschmidt/machine-signing/commit/2013a0bc77efdcd16186917393aa89cfb57647cb))
* **init:** shell-quote the printed gh ssh-key add command ([dda6652](https://github.com/miklschmidt/machine-signing/commit/dda6652deccf9f095470107a718d2f98e03f9703))
* **init:** skip relative PATH entries when choosing the gpg.ssh.program value ([02dde98](https://github.com/miklschmidt/machine-signing/commit/02dde98b04cd835b8e23e0cb4f8d17db89f2c0f4))
* **init:** use uname -n for the host name and document --title in the usage text ([9e89a83](https://github.com/miklschmidt/machine-signing/commit/9e89a83796417d25adeaa7953ad4af930a4fa9f6))
* **key:** say how to recover from a key file the hardware cannot use ([29d6873](https://github.com/miklschmidt/machine-signing/commit/29d687331c1885132c6cda2857e5b9c657f8c9de))
* **key:** write the key file readable only by the user, and never partially ([f78e337](https://github.com/miklschmidt/machine-signing/commit/f78e33773af4c78902106aa2714d9a9d26c652a4))
* **prefer:** keep the agent timeout when ssh-keygen stalls before reading the message ([77312ad](https://github.com/miklschmidt/machine-signing/commit/77312add95abd2446c9909052396435d34372bc3))
* **release:** tag releases as v&lt;version&gt; so asset names match the README ([dc178d8](https://github.com/miklschmidt/machine-signing/commit/dc178d870f3e8fd385c69b71d1c398754dfdedfd))
* **sign:** pass a private key file through to ssh-keygen ([a8c4199](https://github.com/miklschmidt/machine-signing/commit/a8c4199c7ed19b4d6dc14442b1b1c9b521626967))
* **sign:** route by the public key file so an unusable machine key never blocks another key ([52f6645](https://github.com/miklschmidt/machine-signing/commit/52f6645fdcbc0f6ff48f41f739a80d2c831d54fa))
