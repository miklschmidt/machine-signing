{
  description = "machine-signing: sign git commits with a TPM or Secure Enclave key";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  outputs = { self, nixpkgs }:
    let
      lib = nixpkgs.lib;
      linux = [ "x86_64-linux" "aarch64-linux" ];
      forAll = systems: f: lib.genAttrs systems (system: f nixpkgs.legacyPackages.${system});
    in {
      # The macOS build needs Xcode's swiftc, which the Nix sandbox does not have, so the package is Linux only.
      packages = forAll linux (pkgs: {
        default = pkgs.rustPlatform.buildRustPackage {
          pname = "machine-signing";
          version = (lib.importTOML ./Cargo.toml).package.version;
          src = lib.cleanSource ./.;
          cargoLock.lockFile = ./Cargo.lock;
          nativeBuildInputs = [ pkgs.pkg-config ];
          buildInputs = [ pkgs.tpm2-tss ];
          # The end-to-end test runs a software TPM, git and an ssh-agent.
          nativeCheckInputs = [ pkgs.swtpm pkgs.git pkgs.openssh ];
          meta = {
            description = "Sign git commits with a key in the TPM, through git's SSH signing";
            homepage = "https://github.com/miklschmidt/machine-signing";
            license = lib.licenses.mit;
            mainProgram = "machine-signing";
            platforms = lib.platforms.linux;
          };
        };
      });

      devShells = forAll (linux ++ [ "aarch64-darwin" ]) (pkgs: {
        default = pkgs.mkShell {
          packages = with pkgs; [ cargo rustc clippy rustfmt rust-analyzer openssh ]
            ++ lib.optionals stdenv.hostPlatform.isLinux [ pkg-config tpm2-tss swtpm ];
          RUST_SRC_PATH = "${pkgs.rustPlatform.rustLibSrc}";
        };
      });
    };
}
