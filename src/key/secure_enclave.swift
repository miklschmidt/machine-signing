// Secure Enclave backend shim. build.rs compiles this file into a static library.
// Each function returns 0 on success. On failure it returns 1 and writes a UTF-8
// message into `err` (at most `errCap` bytes, not NUL-terminated) and its length into `errLen`.

import CryptoKit
import Foundation
import LocalAuthentication

private func fail(_ message: String, _ err: UnsafeMutablePointer<UInt8>, _ errCap: Int, _ errLen: UnsafeMutablePointer<Int>) -> Int32 {
    let bytes = Array(message.utf8.prefix(errCap))
    for (index, byte) in bytes.enumerated() { err[index] = byte }
    errLen.pointee = bytes.count
    return 1
}

private func write(_ data: Data, _ out: UnsafeMutablePointer<UInt8>, _ outCap: Int, _ outLen: UnsafeMutablePointer<Int>) -> Bool {
    guard data.count <= outCap else { return false }
    data.copyBytes(to: out, count: data.count)
    outLen.pointee = data.count
    return true
}

private func load(
    _ blob: UnsafePointer<UInt8>, _ blobLen: Int, _ context: LAContext? = nil
) throws -> SecureEnclave.P256.Signing.PrivateKey {
    try SecureEnclave.P256.Signing.PrivateKey(
        dataRepresentation: Data(bytes: blob, count: blobLen), authenticationContext: context)
}

/// Whether the error, or an error under it, says that the key needs Touch ID or the password
/// and the context does not allow the prompt.
private func isNotInteractive(_ error: Error) -> Bool {
    var next: NSError? = error as NSError
    while let error = next {
        switch (error.domain, error.code) {
        case (LAErrorDomain, LAError.notInteractive.rawValue),
             (NSOSStatusErrorDomain, Int(errSecInteractionNotAllowed)):
            return true
        default:
            next = error.userInfo[NSUnderlyingErrorKey] as? NSError
        }
    }
    return false
}

/// Creates a key in the Secure Enclave and writes its wrapped `dataRepresentation` blob.
/// When `userPresence` is not 0, each signature needs Touch ID or the login password.
@_cdecl("ms_se_generate")
public func ms_se_generate(
    _ userPresence: Int32,
    _ out: UnsafeMutablePointer<UInt8>, _ outCap: Int, _ outLen: UnsafeMutablePointer<Int>,
    _ err: UnsafeMutablePointer<UInt8>, _ errCap: Int, _ errLen: UnsafeMutablePointer<Int>
) -> Int32 {
    guard SecureEnclave.isAvailable else { return fail("this Mac has no Secure Enclave", err, errCap, errLen) }
    var flags: SecAccessControlCreateFlags = [.privateKeyUsage]
    if userPresence != 0 { flags.insert(.userPresence) }
    guard let access = SecAccessControlCreateWithFlags(
        nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly, flags, nil)
    else { return fail("cannot create the access control of the Secure Enclave key", err, errCap, errLen) }
    do {
        let key = try SecureEnclave.P256.Signing.PrivateKey(accessControl: access)
        guard write(key.dataRepresentation, out, outCap, outLen) else {
            return fail("the Secure Enclave key blob is larger than \(outCap) bytes", err, errCap, errLen)
        }
        return 0
    } catch {
        return fail("cannot create a Secure Enclave key: \(error)", err, errCap, errLen)
    }
}

/// Writes the 65-byte uncompressed SEC1 public key of a blob.
@_cdecl("ms_se_public_key")
public func ms_se_public_key(
    _ blob: UnsafePointer<UInt8>, _ blobLen: Int, _ out: UnsafeMutablePointer<UInt8>,
    _ err: UnsafeMutablePointer<UInt8>, _ errCap: Int, _ errLen: UnsafeMutablePointer<Int>
) -> Int32 {
    do {
        let key = try load(blob, blobLen)
        var len = 0
        guard write(key.publicKey.x963Representation, out, 65, &len), len == 65 else {
            return fail("the Secure Enclave returned a public key that is not 65 bytes", err, errCap, errLen)
        }
        return 0
    } catch {
        return fail("the Secure Enclave refused the saved key: \(error)", err, errCap, errLen)
    }
}

/// Writes 1 to `out` when the key needs Touch ID or the password for each signature, else 0.
/// It signs a test message without a prompt, so it never asks the user.
@_cdecl("ms_se_needs_user_presence")
public func ms_se_needs_user_presence(
    _ blob: UnsafePointer<UInt8>, _ blobLen: Int, _ out: UnsafeMutablePointer<Int32>,
    _ err: UnsafeMutablePointer<UInt8>, _ errCap: Int, _ errLen: UnsafeMutablePointer<Int>
) -> Int32 {
    let context = LAContext()
    context.interactionNotAllowed = true
    do {
        _ = try load(blob, blobLen, context).signature(for: Data("machine-signing probe".utf8))
        out.pointee = 0
        return 0
    } catch where isNotInteractive(error) {
        out.pointee = 1
        return 0
    } catch {
        return fail("the Secure Enclave cannot sign: \(error)", err, errCap, errLen)
    }
}

/// Signs SHA-256 of `msg` and writes the 64-byte r || s signature.
/// A key that needs user presence shows the Touch ID prompt first.
@_cdecl("ms_se_sign")
public func ms_se_sign(
    _ blob: UnsafePointer<UInt8>, _ blobLen: Int, _ msg: UnsafePointer<UInt8>, _ msgLen: Int,
    _ out: UnsafeMutablePointer<UInt8>,
    _ err: UnsafeMutablePointer<UInt8>, _ errCap: Int, _ errLen: UnsafeMutablePointer<Int>
) -> Int32 {
    let context = LAContext()
    context.localizedReason = "sign with your machine-signing key"
    do {
        let signature = try load(blob, blobLen, context).signature(for: Data(bytes: msg, count: msgLen))
        var len = 0
        guard write(signature.rawRepresentation, out, 64, &len), len == 64 else {
            return fail("the Secure Enclave returned a signature that is not 64 bytes", err, errCap, errLen)
        }
        return 0
    } catch where isNotInteractive(error) {
        return fail(
            "the key needs Touch ID or your password, and this session cannot show the prompt, "
                + "for example because it is an SSH session", err, errCap, errLen)
    } catch let error as LAError where error.code == .userCancel {
        return fail("you canceled the Touch ID prompt", err, errCap, errLen)
    } catch {
        return fail("the Secure Enclave cannot sign: \(error)", err, errCap, errLen)
    }
}
