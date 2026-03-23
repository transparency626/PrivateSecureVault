import SwiftUI
import UIKit
import UniformTypeIdentifiers

struct ContentView: View {
    @StateObject private var store = VaultStore()

    var body: some View {
        Group {
            if !store.hasVault {
                CreateScreen(store: store)
            } else if !store.isUnlocked {
                UnlockScreen(store: store)
            } else {
                HomeScreen(store: store)
            }
        }
        .animation(.easeInOut(duration: 0.2), value: store.hasVault)
        .animation(.easeInOut(duration: 0.2), value: store.isUnlocked)
    }
}

private struct CreateScreen: View {
    @ObservedObject var store: VaultStore
    @State private var password = ""
    @State private var confirm = ""
    @State private var busy = false

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(alignment: .leading, spacing: 20) {
                    Text("加密保险箱")
                        .font(.largeTitle.bold())
                    Text("AES-256-GCM 加密文件；口令经 PBKDF2-HMAC-SHA256（约 60 万次迭代）派生密钥。密码无法找回。")
                        .font(.subheadline)
                        .foregroundStyle(.secondary)

                    SecureField("主密码（≥8 位）", text: $password)
                        .textContentType(.newPassword)
                        .textFieldStyle(.roundedBorder)
                    SecureField("确认密码", text: $confirm)
                        .textContentType(.newPassword)
                        .textFieldStyle(.roundedBorder)

                    if let t = store.bannerMessage {
                        Text(t).font(.footnote).foregroundStyle(.red)
                    }

                    Button {
                        Task {
                            busy = true
                            defer { busy = false }
                            _ = await store.createVault(password: password, confirmation: confirm)
                        }
                    } label: {
                        Group {
                            if busy {
                                HStack {
                                    ProgressView()
                                    Text("正在创建…")
                                }
                            } else {
                                Text("创建保险箱")
                            }
                        }
                        .frame(maxWidth: .infinity)
                    }
                    .buttonStyle(.borderedProminent)
                    .disabled(busy || password.isEmpty || confirm.isEmpty)
                }
                .padding(24)
            }
        }
    }
}

private struct UnlockScreen: View {
    @ObservedObject var store: VaultStore
    @State private var password = ""
    @State private var busy = false

    var body: some View {
        NavigationStack {
            VStack(alignment: .leading, spacing: 20) {
                Text("解锁")
                    .font(.largeTitle.bold())
                Text("校验口令需要几秒（PBKDF2）。")
                    .font(.subheadline)
                    .foregroundStyle(.secondary)

                SecureField("主密码", text: $password)
                    .textContentType(.password)
                    .textFieldStyle(.roundedBorder)
                    .submitLabel(.go)
                    .onSubmit { go() }

                if let t = store.bannerMessage {
                    Text(t).font(.footnote).foregroundStyle(.red)
                }

                Button(action: go) {
                    Group {
                        if busy {
                            HStack {
                                ProgressView()
                                Text("解锁中…")
                            }
                        } else {
                            Text("解锁")
                        }
                    }
                    .frame(maxWidth: .infinity)
                }
                .buttonStyle(.borderedProminent)
                .disabled(busy || password.isEmpty)

                Spacer()
            }
            .padding(24)
        }
    }

    private func go() {
        Task {
            busy = true
            defer { busy = false }
            _ = await store.unlock(password: password)
        }
    }
}

private struct ShareItem: Identifiable {
    let id = UUID()
    let url: URL
}

private struct HomeScreen: View {
    @ObservedObject var store: VaultStore
    @State private var pick = false
    @State private var dropOn = false
    @State private var shareItem: ShareItem?

    var body: some View {
        NavigationStack {
            VStack(spacing: 0) {
                if let t = store.bannerMessage {
                    Text(t)
                        .font(.footnote)
                        .foregroundStyle(.red)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .padding(10)
                        .background(Color.red.opacity(0.12))
                }

                List {
                    Section {
                        dropZone
                    } header: { Text("添加文件") }

                    Section {
                        if store.entries.isEmpty {
                            Text("暂无文件").foregroundStyle(.secondary)
                        } else {
                            ForEach(store.entries) { e in
                                Row(
                                    entry: e,
                                    onShare: {
                                        if let u = await store.decryptToTempURL(for: e) {
                                            shareItem = ShareItem(url: u)
                                        }
                                    },
                                    onDelete: { store.deleteEntry(e) }
                                )
                            }
                        }
                    } header: { Text("已加密") }
                }
            }
            .navigationTitle("保险箱")
            .toolbar {
                ToolbarItem(placement: .topBarLeading) {
                    Button("锁定") { store.lockVault() }
                }
                ToolbarItem(placement: .topBarTrailing) {
                    Button("导入") { pick = true }
                }
            }
            .fileImporter(isPresented: $pick, allowedContentTypes: [.item], allowsMultipleSelection: true) { r in
                if case .success(let urls) = r {
                    Task { for u in urls { await store.importFile(from: u) } }
                }
            }
            .sheet(item: $shareItem) { item in
                ShareSheet(items: [item.url]) {
                    try? FileManager.default.removeItem(at: item.url)
                    shareItem = nil
                }
            }
        }
    }

    private var dropZone: some View {
        RoundedRectangle(cornerRadius: 14, style: .continuous)
            .strokeBorder(
                dropOn ? Color.accentColor : Color.secondary.opacity(0.35),
                style: StrokeStyle(lineWidth: 2, dash: [7, 5])
            )
            .background(
                RoundedRectangle(cornerRadius: 14, style: .continuous)
                    .fill(dropOn ? Color.accentColor.opacity(0.1) : Color.secondary.opacity(0.06))
            )
            .frame(height: 110)
            .overlay {
                VStack(spacing: 6) {
                    Image(systemName: "arrow.down.doc")
                    Text("拖入文件").font(.subheadline)
                    Text("或点「导入」").font(.caption).foregroundStyle(.secondary)
                }
            }
            .onDrop(of: [.fileURL], isTargeted: $dropOn) { providers in
                Task {
                    for p in providers {
                        let u = await readURL(p)
                        if let u { await store.importFile(from: u) }
                    }
                }
                return true
            }
    }

    private func readURL(_ p: NSItemProvider) async -> URL? {
        await withCheckedContinuation { c in
            p.loadItem(forTypeIdentifier: UTType.fileURL.identifier, options: nil) { item, _ in
                c.resume(returning: item as? URL)
            }
        }
    }
}

private struct Row: View {
    let entry: VaultEntry
    var onShare: () async -> Void
    var onDelete: () -> Void
    @State private var busy = false

    private var sizeText: String {
        let f = ByteCountFormatter()
        f.countStyle = .file
        return f.string(fromByteCount: entry.byteSize)
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            Text(entry.displayName).font(.headline)
            Text(sizeText).font(.caption).foregroundStyle(.secondary)
        }
        .swipeActions(edge: .trailing, allowsFullSwipe: false) {
            Button(role: .destructive) { onDelete() } label: {
                Label("删除", systemImage: "trash")
            }
            Button {
                Task { @MainActor in
                    busy = true
                    await onShare()
                    busy = false
                }
            } label: {
                Label("解密分享", systemImage: "square.and.arrow.up")
            }
            .tint(.blue)
            .disabled(busy)
        }
    }
}

private struct ShareSheet: UIViewControllerRepresentable {
    var items: [Any]
    var onFinish: () -> Void

    func makeUIViewController(context: Context) -> UIActivityViewController {
        let vc = UIActivityViewController(activityItems: items, applicationActivities: nil)
        vc.completionWithItemsHandler = { _, _, _, _ in
            DispatchQueue.main.async(execute: onFinish)
        }
        return vc
    }

    func updateUIViewController(_ uiViewController: UIActivityViewController, context: Context) {}
}

#Preview {
    ContentView()
}
