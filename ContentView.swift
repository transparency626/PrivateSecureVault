import CryptoKit
import SwiftUI
import UniformTypeIdentifiers

struct ContentView: View {
    private let columns = [
        GridItem(.flexible(), spacing: 16),
        GridItem(.flexible(), spacing: 16),
        GridItem(.flexible(), spacing: 16),
        GridItem(.flexible(), spacing: 16),
    ]

    @State private var rows: [(UUID, String)] = []
    @State private var pick = false
    @State private var askPass = false
    @State private var password = ""
    @State private var pickedURL: URL?

    private var vaultRoot: URL {
        FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)[0]
            .appendingPathComponent("vault", isDirectory: true)
    }

    var body: some View {
        NavigationStack {
            ZStack(alignment: .bottomTrailing) {
                ScrollView {
                    VStack(alignment: .leading, spacing: 12) {
                        Text("加密文件")
                            .font(.title2.weight(.semibold))
                            .padding(.horizontal, 4)

                        LazyVGrid(columns: columns, spacing: 20) {
                            ForEach(rows, id: \.0) { _, name in
                                fileCell(title: name)
                            }
                        }
                        .padding(.top, 4)
                    }
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(.horizontal, 16)
                    .padding(.bottom, 100)
                }

                Button {
                    pick = true
                } label: {
                    Label("选择文件", systemImage: "folder.badge.plus")
                        .font(.subheadline.weight(.semibold))
                        .padding(.horizontal, 18)
                        .padding(.vertical, 12)
                }
                .buttonStyle(.borderedProminent)
                .tint(.blue)
                .clipShape(Capsule())
                .shadow(color: .black.opacity(0.18), radius: 10, y: 4)
                .padding(.trailing, 20)
                .padding(.bottom, 28)
            }
            .navigationTitle("加密保险箱")
            .navigationBarTitleDisplayMode(.large)
            .background(Color(.systemGroupedBackground))
            .fileImporter(isPresented: $pick, allowedContentTypes: [UTType.item], allowsMultipleSelection: false) { r in
                guard case .success(let urls) = r, let u = urls.first else { return }
                _ = u.startAccessingSecurityScopedResource()
                pickedURL = u
                askPass = true
            }
            .alert("输入密码", isPresented: $askPass) {
                SecureField("密码", text: $password)
                Button("加密并保存") {
                    guard let url = pickedURL else { return }
                    defer {
                        url.stopAccessingSecurityScopedResource()
                        pickedURL = nil
                        password = ""
                    }
                    guard !password.isEmpty, let plain = try? Data(contentsOf: url) else { return }
                    let salt = Data((0..<16).map { _ in UInt8.random(in: 0...255) })
                    let key = SymmetricKey(data: Data(SHA256.hash(data: Data(password.utf8) + salt)))
                    guard let sealed = try? AES.GCM.seal(plain, using: key), let combined = sealed.combined else { return }
                    let blob = salt + combined
                    let id = UUID()
                    try? FileManager.default.createDirectory(at: vaultRoot, withIntermediateDirectories: true)
                    try? blob.write(to: vaultRoot.appendingPathComponent("\(id.uuidString).bin"))
                    rows.append((id, url.lastPathComponent))
                    let idx = rows.map { ["id": $0.0.uuidString, "name": $0.1] }
                    if let j = try? JSONSerialization.data(withJSONObject: idx) {
                        try? j.write(to: vaultRoot.appendingPathComponent("index.json"))
                    }
                }
                Button("取消", role: .cancel) {
                    pickedURL?.stopAccessingSecurityScopedResource()
                    pickedURL = nil
                    password = ""
                }
            } message: {
                Text("用于加密所选文件")
            }
            .onAppear {
                let p = vaultRoot.appendingPathComponent("index.json")
                guard let d = try? Data(contentsOf: p),
                      let a = try? JSONSerialization.jsonObject(with: d) as? [[String: String]] else { return }
                rows = a.compactMap { g in
                    guard let s = g["id"], let u = UUID(uuidString: s), let n = g["name"] else { return nil }
                    return (u, n)
                }
            }
        }
    }

    private func fileCell(title: String) -> some View {
        VStack(spacing: 8) {
            ZStack {
                RoundedRectangle(cornerRadius: 12, style: .continuous)
                    .fill(Color(.secondarySystemGroupedBackground))
                    .shadow(color: .black.opacity(0.06), radius: 4, y: 2)
                    .frame(height: 88)
                Image(systemName: "lock.doc.fill")
                    .font(.system(size: 36))
                    .symbolRenderingMode(.hierarchical)
                    .foregroundStyle(.secondary)
            }
            Text(title)
                .font(.caption)
                .foregroundStyle(.primary)
                .lineLimit(2)
                .multilineTextAlignment(.center)
                .frame(maxWidth: .infinity)
        }
    }
}

#Preview { ContentView() }
