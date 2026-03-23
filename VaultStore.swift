import Combine
import CryptoKit
import Foundation

struct VaultEntry: Identifiable, Equatable {
    let id: UUID
    let displayName: String
    let encryptedPath: String
    let byteSize: Int64
    let addedAt: Date
}

@MainActor
final class VaultStore: ObservableObject {
    @Published private(set) var hasVault = false
    @Published private(set) var isUnlocked = false
    @Published private(set) var entries: [VaultEntry] = []
    @Published var bannerMessage: String?

    private let fm = FileManager.default
    private var masterKeyData: Data?

    private var vaultDir: URL {
        let base = fm.urls(for: .applicationSupportDirectory, in: .userDomainMask).first!
        let d = base.appendingPathComponent("PrivateSecureVault", isDirectory: true)
        if !fm.fileExists(atPath: d.path) {
            try? fm.createDirectory(at: d, withIntermediateDirectories: true)
        }
        return d
    }

    private var rootFile: URL { vaultDir.appendingPathComponent("vault.root") }

    private var itemsDir: URL {
        let d = vaultDir.appendingPathComponent("items", isDirectory: true)
        if !fm.fileExists(atPath: d.path) {
            try? fm.createDirectory(at: d, withIntermediateDirectories: true)
        }
        return d
    }

    init() {
        hasVault = fm.fileExists(atPath: rootFile.path)
    }

    func clearBanner() { bannerMessage = nil }

    func createVault(password: String, confirmation: String) async -> Bool {
        clearBanner()
        if password.count < 8 {
            bannerMessage = VaultError.passwordTooShort.localizedDescription
            return false
        }
        if password != confirmation {
            bannerMessage = VaultError.passwordMismatch.localizedDescription
            return false
        }
        do {
            let (env, mat) = try await Task.detached(priority: .userInitiated) {
                let (e, k) = try VaultCrypto.createRoot(password: password)
                return (e, k.vaultKeyData)
            }.value
            try env.write(to: rootFile, options: .atomic)
            hasVault = true
            masterKeyData = mat
            isUnlocked = true
            entries = []
            await reloadEntries()
            return true
        } catch {
            bannerMessage = error.localizedDescription
            return false
        }
    }

    func unlock(password: String) async -> Bool {
        clearBanner()
        guard let env = try? Data(contentsOf: rootFile), !env.isEmpty else {
            bannerMessage = "未找到保险箱"
            return false
        }
        let mat = await Task.detached(priority: .userInitiated) { () -> Data? in
            do {
                guard let k = try VaultCrypto.unlockMasterKey(password: password, envelope: env) else { return nil }
                return k.vaultKeyData
            } catch {
                return nil
            }
        }.value
        guard let mat else {
            bannerMessage = VaultError.wrongPassword.localizedDescription
            return false
        }
        masterKeyData = mat
        isUnlocked = true
        await reloadEntries()
        return true
    }

    func lockVault() {
        masterKeyData = nil
        isUnlocked = false
        entries = []
        clearBanner()
    }

    func importFile(from url: URL) async {
        clearBanner()
        guard let mat = masterKeyData else {
            bannerMessage = "请先解锁"
            return
        }
        let access = url.startAccessingSecurityScopedResource()
        defer { if access { url.stopAccessingSecurityScopedResource() } }
        let name = url.lastPathComponent
        let dirPath = itemsDir.path
        do {
            let raw = try Data(contentsOf: url)
            try await Task.detached(priority: .userInitiated) {
                let key = SymmetricKey(data: mat)
                let inner = try VaultPayload.pack(name: name, bytes: raw)
                let sealed = try VaultCrypto.seal(inner, key: key)
                let blob = VaultCrypto.wrapFile(sealed)
                let id = UUID()
                let out = URL(fileURLWithPath: dirPath).appendingPathComponent("\(id.uuidString).psvault")
                try blob.write(to: out, options: .atomic)
            }.value
            await reloadEntries()
        } catch {
            bannerMessage = error.localizedDescription
        }
    }

    func decryptToTempURL(for entry: VaultEntry) async -> URL? {
        clearBanner()
        guard let mat = masterKeyData else {
            bannerMessage = "请先解锁"
            return nil
        }
        let src = URL(fileURLWithPath: entry.encryptedPath)
        do {
            let tmp: URL = try await Task.detached(priority: .userInitiated) {
                let key = SymmetricKey(data: mat)
                let blob = try Data(contentsOf: src)
                let combined = try VaultCrypto.unwrapFile(blob)
                let plain = try VaultCrypto.open(combined, key: key)
                let (_, body) = try VaultPayload.unpack(plain)
                let u = FileManager.default.temporaryDirectory
                    .appendingPathComponent(UUID().uuidString + "_" + entry.displayName)
                try body.write(to: u, options: .atomic)
                return u
            }.value
            return tmp
        } catch {
            bannerMessage = error.localizedDescription
            return nil
        }
    }

    func deleteEntry(_ entry: VaultEntry) {
        clearBanner()
        do {
            try fm.removeItem(atPath: entry.encryptedPath)
            entries.removeAll { $0.id == entry.id }
        } catch {
            bannerMessage = error.localizedDescription
        }
    }

    func reloadEntries() async {
        guard let mat = masterKeyData else { return }
        let folder = itemsDir.path
        let list = await Task.detached(priority: .utility) {
            Self.scan(folder: folder, keyMaterial: mat)
        }.value
        entries = list
    }

    nonisolated private static func scan(folder: String, keyMaterial: Data) -> [VaultEntry] {
        let key = SymmetricKey(data: keyMaterial)
        let fm = FileManager.default
        let dir = URL(fileURLWithPath: folder, isDirectory: true)
        guard let urls = try? fm.contentsOfDirectory(
            at: dir,
            includingPropertiesForKeys: [.fileSizeKey, .creationDateKey],
            options: [.skipsHiddenFiles]
        ) else { return [] }
        var rows: [VaultEntry] = []
        for u in urls where u.pathExtension.lowercased() == "psvault" {
            guard let id = UUID(uuidString: u.deletingPathExtension().lastPathComponent) else { continue }
            guard let rv = try? u.resourceValues(forKeys: [.fileSizeKey, .creationDateKey]),
                  let size = rv.fileSize else { continue }
            guard let blob = try? Data(contentsOf: u),
                  let combined = try? VaultCrypto.unwrapFile(blob),
                  let plain = try? VaultCrypto.open(combined, key: key),
                  let (nm, _) = try? VaultPayload.unpack(plain) else { continue }
            rows.append(VaultEntry(
                id: id,
                displayName: nm,
                encryptedPath: u.path,
                byteSize: Int64(size),
                addedAt: rv.creationDate ?? .distantPast
            ))
        }
        rows.sort { $0.addedAt > $1.addedAt }
        return rows
    }
}
