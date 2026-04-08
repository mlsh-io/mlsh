import SwiftUI
import AppKit

struct EmptyStateView: View {
    let onOpenFolder: () -> Void

    var body: some View {
        VStack(spacing: Theme.Spacing.md) {
            Image(systemName: "folder.badge.plus")
                .font(.largeTitle)
                .foregroundStyle(.secondary)

            VStack(spacing: Theme.Spacing.xs) {
                Text("No Clusters Configured")
                    .font(.headline)

                Text("Add cluster configs to:")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }

            HStack(spacing: Theme.Spacing.sm) {
                Text("~/.config/mlsh/clusters/")
                    .font(.system(.caption, design: .monospaced))
                    .padding(.horizontal, Theme.Spacing.sm)
                    .padding(.vertical, Theme.Spacing.xs)
                    .background(
                        RoundedRectangle(cornerRadius: 4)
                            .fill(Color.secondary.opacity(0.1))
                    )
                    .textSelection(.enabled)

                Button(action: copyPath) {
                    Image(systemName: "doc.on.doc")
                        .font(.caption)
                }
                .buttonStyle(.plain)
                .foregroundStyle(.secondary)
                .help("Copy path")
            }

            Button(action: onOpenFolder) {
                Label("Open Folder", systemImage: "folder")
                    .font(.caption)
            }
            .buttonStyle(.bordered)
            .controlSize(.small)
        }
        .frame(maxWidth: .infinity)
        .padding(.vertical, Theme.Spacing.xl)
    }

    private func copyPath() {
        let home = FileManager.default.homeDirectoryForCurrentUser.path
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString("\(home)/.config/mlsh/clusters/", forType: .string)
    }
}
