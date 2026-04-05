import SwiftUI

/// 纯视觉雏形：占位「已导入的加密文件」，无业务逻辑。
private let prototypeFileTitles = [
    "季度报告.pdf",
    "扫描件_2024.png",
    "合同草案.docx",
    "备忘录.txt",
    "旅行照片.heic",
]

struct ContentView: View {
    private let columns = [
        GridItem(.flexible(), spacing: 16),
        GridItem(.flexible(), spacing: 16),
        GridItem(.flexible(), spacing: 16),
        GridItem(.flexible(), spacing: 16),
    ]

    var body: some View {
        NavigationStack {
            ZStack(alignment: .bottomTrailing) {
                ScrollView {
                    VStack(alignment: .leading, spacing: 12) {
                        Text("加密文件")
                            .font(.title2.weight(.semibold))
                            .padding(.horizontal, 4)

                        LazyVGrid(columns: columns, spacing: 20) {
                            ForEach(prototypeFileTitles, id: \.self) { title in
                                fileCell(title: title)
                            }
                        }
                        .padding(.top, 4)
                    }
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(.horizontal, 16)
                    .padding(.bottom, 100)
                }

                selectFileButton
                    .padding(.trailing, 20)
                    .padding(.bottom, 28)
            }
            .navigationTitle("加密保险箱")
            .navigationBarTitleDisplayMode(.large)
            .background(Color(.systemGroupedBackground))
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

    private var selectFileButton: some View {
        Button(action: {}) {
            Label("选择文件", systemImage: "folder.badge.plus")
                .font(.subheadline.weight(.semibold))
                .padding(.horizontal, 18)
                .padding(.vertical, 12)
        }
        .buttonStyle(.borderedProminent)
        .tint(.blue)
        .clipShape(Capsule())
        .shadow(color: .black.opacity(0.18), radius: 10, y: 4)
    }
}

#Preview { ContentView() }
