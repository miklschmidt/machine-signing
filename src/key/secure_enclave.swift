// Secure Enclave backend shim. build.rs compiles this file into a static library.
// Each function returns 0 on success. On failure it returns 1 and writes a UTF-8
// message into `err` (at most `errCap` bytes, not NUL-terminated) and its length into `errLen`.

import CryptoKit
import Foundation

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

private func load(_ blob: UnsafePointer<UInt8>, _ blobLen: Int) throws -> SecureEnclave.P256.Signing.PrivateKey {
    try SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: Data(bytes: blob, count: blobLen))
}

/// Creates a key in the Secure Enclave and writes its wrapped `dataRepresentation` blob.
@_cdecl("ms_se_generate")
public func ms_se_generate(
    _ out: UnsafeMutablePointer<UInt8>, _ outCap: Int, _ outLen: UnsafeMutablePointer<Int>,
    _ err: UnsafeMutablePointer<UInt8>, _ errCap: Int, _ errLen: UnsafeMutablePointer<Int>
) -> Int32 {
    guard SecureEnclave.isAvailable else { return fail("this Mac has no Secure Enclave", err, errCap, errLen) }
    do {
        let key = try SecureEnclave.P256.Signing.PrivateKey()
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
        return fail("the Secure Enclave refused the saved key. The key file comes from another Mac: \(error)", err, errCap, errLen)
    }
}

/// Signs SHA-256 of `msg` and writes the 64-byte r || s signature.
@_cdecl("ms_se_sign")
public func ms_se_sign(
    _ blob: UnsafePointer<UInt8>, _ blobLen: Int, _ msg: UnsafePointer<UInt8>, _ msgLen: Int,
    _ out: UnsafeMutablePointer<UInt8>,
    _ err: UnsafeMutablePointer<UInt8>, _ errCap: Int, _ errLen: UnsafeMutablePointer<Int>
) -> Int32 {
    do {
        let signature = try load(blob, blobLen).signature(for: Data(bytes: msg, count: msgLen))
        var len = 0
        guard write(signature.rawRepresentation, out, 64, &len), len == 64 else {
            return fail("the Secure Enclave returned a signature that is not 64 bytes", err, errCap, errLen)
        }
        return 0
    } catch {
        return fail("the Secure Enclave cannot sign: \(error)", err, errCap, errLen)
    }
}
