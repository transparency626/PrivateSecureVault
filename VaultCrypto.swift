import CryptoKit
import Foundation
import Security

enum VaultError: Error, LocalizedError {
    case badFileFormat
    case wrongPassword
    case passwordTooShort
    case passwordMismatch

    var errorDescription: String? {
        switch self {
        case .badFileFormat: return "文件格式无效或已损坏"
        case .wrongPassword: return "密码错误"
        case .passwordTooShort: return "密码至少 8 位"
        case .passwordMismatch: return "两次输入的密码不一致"
        }
    }
}

/// AES-256-GCM + PBKDF2-HMAC-SHA256（慢哈希）派生 256 位主密钥。
enum VaultCrypto {
    private static let rootMagic = Data("PSVR".utf8)
    private static let fileMagic = Data("PSDT".utf8)
    private static let saltCount = 32
    private static let verifierPlain = Data("PrivateSecureVault.v1".utf8)

    static let pbkdf2Iterations = 600_000

    static func randomSalt() -> Data {
        var b = [UInt8](repeating: 0, count: saltCount)
        _ = SecRandomCopyBytes(kSecRandomDefault, saltCount, &b)
        return Data(b)
    }

    static func deriveKey(password: String, salt: Data) throws -> SymmetricKey {
        let d = try pbkdf2SHA256(pw: Data(password.utf8), salt: salt, iterations: pbkdf2Iterations, dkLen: 32)
        return SymmetricKey(data: d)
    }

    private static func pbkdf2SHA256(pw: Data, salt: Data, iterations: Int, dkLen: Int) throws -> Data {
        let hLen = 32
        let blocks = Int(ceil(Double(dkLen) / Double(hLen)))
        let r = dkLen - (blocks - 1) * hLen
        var out = Data()
        out.reserveCapacity(dkLen)
        for block in 1...blocks {
            var u = try hmacSHA256(key: pw, data: salt + be32(block))
            var t = u
            for _ in 1..<iterations {
                u = try hmacSHA256(key: pw, data: u)
                t = xor(t, u)
            }
            let take = (block == blocks) ? r : hLen
            out.append(t.prefix(take))
        }
        precondition(out.count == dkLen)
        return out
    }

    private static func be32(_ i: Int) -> Data {
        let u = UInt32(i)
        return Data([
            UInt8((u >> 24) & 0xff), UInt8((u >> 16) & 0xff),
            UInt8((u >> 8) & 0xff), UInt8(u & 0xff),
        ])
    }

    private static func hmacSHA256(key: Data, data: Data) throws -> Data {
        let sk = SymmetricKey(data: key)
        return Data(HMAC<SHA256>.authenticationCode(for: data, using: sk))
    }

    private static func xor(_ a: Data, _ b: Data) -> Data {
        Data(zip(a, b).map { $0 ^ $1 })
    }

    static func seal(_ plain: Data, key: SymmetricKey) throws -> Data {
        let box = try AES.GCM.seal(plain, using: key)
        guard let c = box.combined else { throw VaultError.badFileFormat }
        return c
    }

    static func open(_ combined: Data, key: SymmetricKey) throws -> Data {
        let box = try AES.GCM.SealedBox(combined: combined)
        return try AES.GCM.open(box, using: key)
    }

    /// 新建根信封 + 主密钥（PBKDF2 只跑一次）。
    static func createRoot(password: String) throws -> (envelope: Data, masterKey: SymmetricKey) {
        let salt = randomSalt()
        let key = try deriveKey(password: password, salt: salt)
        let sealed = try seal(verifierPlain, key: key)
        return (rootMagic + salt + sealed, key)
    }

    private static func parseRoot(_ data: Data) throws -> (salt: Data, sealed: Data) {
        let need = rootMagic.count + saltCount
        guard data.count > need else { throw VaultError.badFileFormat }
        guard data.prefix(rootMagic.count) == rootMagic else { throw VaultError.badFileFormat }
        let tail = data.dropFirst(rootMagic.count)
        let salt = Data(tail.prefix(saltCount))
        let sealed = Data(tail.dropFirst(saltCount))
        guard !sealed.isEmpty else { throw VaultError.badFileFormat }
        return (salt, sealed)
    }

    static func unlockMasterKey(password: String, envelope: Data) throws -> SymmetricKey? {
        let (salt, sealed) = try parseRoot(envelope)
        let key = try deriveKey(password: password, salt: salt)
        guard let p = try? open(sealed, key: key), p == verifierPlain else { return nil }
        return key
    }

    static func wrapFile(_ combined: Data) -> Data { fileMagic + combined }

    static func unwrapFile(_ data: Data) throws -> Data {
        guard data.count > fileMagic.count else { throw VaultError.badFileFormat }
        guard data.prefix(fileMagic.count) == fileMagic else { throw VaultError.badFileFormat }
        return Data(data.dropFirst(fileMagic.count))
    }
}

enum VaultPayload {
    static func pack(name: String, bytes: Data) throws -> Data {
        guard let nd = name.data(using: .utf8) else { throw VaultError.badFileFormat }
        guard nd.count <= Int(UInt32.max) - 4 else { throw VaultError.badFileFormat }
        let c = UInt32(nd.count)
        var o = Data()
        o.append(UInt8((c >> 24) & 0xff))
        o.append(UInt8((c >> 16) & 0xff))
        o.append(UInt8((c >> 8) & 0xff))
        o.append(UInt8(c & 0xff))
        o.append(nd)
        o.append(bytes)
        return o
    }

    static func unpack(_ plain: Data) throws -> (name: String, bytes: Data) {
        guard plain.count >= 4 else { throw VaultError.badFileFormat }
        let n = Int(
            (UInt32(plain[0]) << 24) | (UInt32(plain[1]) << 16)
                | (UInt32(plain[2]) << 8) | UInt32(plain[3])
        )
        guard plain.count >= 4 + n else { throw VaultError.badFileFormat }
        let nameData = plain.subdata(in: 4..<(4 + n))
        guard let name = String(data: nameData, encoding: .utf8) else { throw VaultError.badFileFormat }
        let body = plain.subdata(in: (4 + n)..<plain.endIndex)
        return (name, body)
    }
}

extension SymmetricKey {
    /// 部分 Xcode / SDK 下 `SymmetricKey` 没有 `rawRepresentation`，用 `ContiguousBytes` 导出即可。
    var vaultKeyData: Data {
        withUnsafeBytes { Data($0) }
    }
}
