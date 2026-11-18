//! Secure Enclave backend (macOS on Apple silicon).
//!
//! CryptoKit has no C API, so `secure_enclave.swift` exports C functions that build.rs links in.
//! The blob is CryptoKit's `dataRepresentation`: the key wrapped by this Mac's Secure Enclave.
//! Storing the key in the keychain instead would need entitlements that an unsigned CLI does not have.

use anyhow::{Result, anyhow};
use p256::ecdsa::Signature;

unsafe extern "C" {
    fn ms_se_generate(
        user_presence: i32,
        out: *mut u8,
        out_cap: usize,
        out_len: *mut usize,
        err: *mut u8,
        err_cap: usize,
        err_len: *mut usize,
    ) -> i32;
    fn ms_se_public_key(
        blob: *const u8,
        blob_len: usize,
        out: *mut u8,
        err: *mut u8,
        err_cap: usize,
        err_len: *mut usize,
    ) -> i32;
    fn ms_se_needs_user_presence(
        blob: *const u8,
        blob_len: usize,
        out: *mut i32,
        err: *mut u8,
        err_cap: usize,
        err_len: *mut usize,
    ) -> i32;
    fn ms_se_sign(
        blob: *const u8,
        blob_len: usize,
        msg: *const u8,
        msg_len: usize,
        out: *mut u8,
        err: *mut u8,
        err_cap: usize,
        err_len: *mut usize,
    ) -> i32;
}

/// Calls a shim function with an error buffer and turns a failure into its message.
fn call(f: impl FnOnce(*mut u8, usize, *mut usize) -> i32) -> Result<()> {
    let mut err = [0u8; 512];
    let mut err_len = 0;
    match f(err.as_mut_ptr(), err.len(), &mut err_len) {
        0 => Ok(()),
        _ => Err(anyhow!("{}", String::from_utf8_lossy(&err[..err_len]))),
    }
}

/// With `touch_id`, each signature needs Touch ID or the login password. This cannot change later.
pub fn generate(touch_id: bool) -> Result<Vec<u8>> {
    let mut blob = vec![0u8; 4096];
    let mut len = 0;
    // SAFETY: every pointer is valid for the capacity passed beside it.
    call(|err, cap, err_len| unsafe {
        ms_se_generate(
            touch_id.into(),
            blob.as_mut_ptr(),
            blob.len(),
            &mut len,
            err,
            cap,
            err_len,
        )
    })?;
    blob.truncate(len);
    Ok(blob)
}

pub fn public_key(blob: &[u8]) -> Result<Vec<u8>> {
    let mut sec1 = vec![0u8; 65];
    // SAFETY: `blob` is valid for its length and `sec1` holds the 65 bytes the shim writes.
    call(|err, cap, err_len| unsafe {
        ms_se_public_key(
            blob.as_ptr(),
            blob.len(),
            sec1.as_mut_ptr(),
            err,
            cap,
            err_len,
        )
    })?;
    Ok(sec1)
}

/// Whether each signature needs Touch ID or the password. Asks the Secure Enclave without a prompt.
pub fn needs_touch_id(blob: &[u8]) -> Result<bool> {
    let mut needs = 0;
    // SAFETY: `blob` is valid for its length and `needs` is a valid i32.
    call(|err, cap, err_len| unsafe {
        ms_se_needs_user_presence(blob.as_ptr(), blob.len(), &mut needs, err, cap, err_len)
    })?;
    Ok(needs != 0)
}

/// CryptoKit hashes `data` with SHA-256 before signing, as ECDSA-SHA256 requires.
pub fn sign(blob: &[u8], data: &[u8]) -> Result<Signature> {
    let mut raw = [0u8; 64];
    // SAFETY: `blob` and `data` are valid for their lengths and `raw` holds the 64 bytes the shim writes.
    call(|err, cap, err_len| unsafe {
        ms_se_sign(
            blob.as_ptr(),
            blob.len(),
            data.as_ptr(),
            data.len(),
            raw.as_mut_ptr(),
            err,
            cap,
            err_len,
        )
    })?;
    Ok(Signature::from_slice(&raw)?)
}
