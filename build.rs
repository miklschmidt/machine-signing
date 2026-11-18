//! On macOS, compiles the Secure Enclave shim (src/key/secure_enclave.swift) into a static library.
//! Needs the Xcode Command Line Tools. Other targets build nothing here.

use std::path::PathBuf;
use std::process::Command;

fn main() {
    let os = std::env::var("CARGO_CFG_TARGET_OS").unwrap();
    let arch = std::env::var("CARGO_CFG_TARGET_ARCH").unwrap();
    if os != "macos" || arch != "aarch64" {
        return;
    }
    let source = "src/key/secure_enclave.swift";
    println!("cargo:rerun-if-changed={source}");
    println!("cargo:rerun-if-env-changed=MACOSX_DEPLOYMENT_TARGET");
    let out = PathBuf::from(std::env::var("OUT_DIR").unwrap());
    let target = format!(
        "arm64-apple-macosx{}",
        std::env::var("MACOSX_DEPLOYMENT_TARGET").unwrap_or_else(|_| "11.0".into())
    );
    let status = Command::new("xcrun")
        .args(["swiftc", "-emit-library", "-static", "-parse-as-library", "-O"])
        .args(["-module-name", "MachineSigningSecureEnclave", "-target", &target, source, "-o"])
        .arg(out.join("libmachine_signing_se.a"))
        .status()
        .expect("cannot run xcrun swiftc: install the Xcode Command Line Tools with `xcode-select --install`");
    assert!(status.success(), "swiftc failed to compile {source}");

    let sdk = Command::new("xcrun")
        .args(["--sdk", "macosx", "--show-sdk-path"])
        .output()
        .unwrap();
    let sdk = String::from_utf8(sdk.stdout).unwrap();
    println!("cargo:rustc-link-search=native={}", out.display());
    println!("cargo:rustc-link-lib=static=machine_signing_se");
    // The static library's objects ask for the Swift runtime and CryptoKit by autolink entries.
    println!(
        "cargo:rustc-link-search=native={}/usr/lib/swift",
        sdk.trim()
    );
    println!("cargo:rustc-link-lib=framework=CryptoKit");
    println!("cargo:rustc-link-lib=framework=Foundation");
    println!("cargo:rustc-link-arg=-Wl,-rpath,/usr/lib/swift");
}
