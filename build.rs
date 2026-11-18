//! On macOS, compiles the Secure Enclave shim (src/key/secure_enclave.swift) into a static library.
//! Needs the Xcode Command Line Tools. Other targets build nothing here.

use std::path::{Path, PathBuf};
use std::process::Command;

fn main() {
    // Without this, every change in the package reruns the build script and relinks the binary.
    println!("cargo:rerun-if-changed=build.rs");
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

    println!("cargo:rustc-link-search=native={}", out.display());
    println!("cargo:rustc-link-lib=static=machine_signing_se");
    // The static library's objects ask for the Swift runtime, its back-deployment
    // libraries (swiftCompatibility56 and others) and the frameworks by autolink entries.
    // The runtime's .tbd files are in the SDK, the back-deployment archives in the toolchain.
    let sdk = xcrun(&["--sdk", "macosx", "--show-sdk-path"]);
    println!("cargo:rustc-link-search=native={sdk}/usr/lib/swift");
    let swiftc = xcrun(&["--find", "swiftc"]);
    let usr = Path::new(&swiftc)
        .ancestors()
        .nth(2)
        .expect("swiftc is in <toolchain>/usr/bin");
    println!(
        "cargo:rustc-link-search=native={}",
        usr.join("lib/swift/macosx").display()
    );
    println!("cargo:rustc-link-lib=framework=CryptoKit");
    println!("cargo:rustc-link-lib=framework=CryptoTokenKit");
    println!("cargo:rustc-link-lib=framework=Foundation");
    println!("cargo:rustc-link-lib=framework=LocalAuthentication");
    println!("cargo:rustc-link-lib=framework=Security");
    println!("cargo:rustc-link-arg=-Wl,-rpath,/usr/lib/swift");
}

/// Runs xcrun and returns its trimmed output.
fn xcrun(args: &[&str]) -> String {
    let output = Command::new("xcrun").args(args).output().unwrap();
    assert!(output.status.success(), "xcrun {} failed", args.join(" "));
    String::from_utf8(output.stdout).unwrap().trim().to_owned()
}
