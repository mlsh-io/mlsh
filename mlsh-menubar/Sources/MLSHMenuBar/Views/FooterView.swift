import SwiftUI
import AppKit

struct FooterView: View {
    let version: String
    let lastMessage: String?
    let availableUpdate: UpdateChecker.Release?
    let onOpenConfig: () -> Void
    let onInstallUpdate: () -> Void

    var body: some View {
        VStack(spacing: 0) {
            // Toast message
            if let msg = lastMessage {
                HStack(spacing: Theme.Spacing.xs) {
                    Image(systemName: "info.circle")
                        .font(.caption2)
                    Text(msg)
                        .font(.caption2)
                        .lineLimit(1)
                }
                .foregroundStyle(.secondary)
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(.horizontal, Theme.Spacing.lg)
                .padding(.vertical, Theme.Spacing.xs)
                .background(Color.secondary.opacity(0.06))
                .transition(.move(edge: .bottom).combined(with: .opacity))
            }

            // Footer bar
            HStack {
                Button(action: onOpenConfig) {
                    Image(systemName: "gearshape")
                        .font(.subheadline)
                        .foregroundStyle(.secondary)
                }
                .buttonStyle(.plain)
                .help("Open config folder")

                if let update = availableUpdate {
                    Button(action: onInstallUpdate) {
                        HStack(spacing: 3) {
                            Image(systemName: "arrow.down.circle.fill")
                                .font(.caption2)
                            Text(update.tag)
                                .font(.caption2)
                        }
                        .foregroundStyle(Theme.Colors.connected)
                    }
                    .buttonStyle(.plain)
                    .help("Update available — click to install")
                } else {
                    Text("\(version)")
                        .font(.caption2)
                        .foregroundStyle(.tertiary)
                }

                Spacer()

                Button("Quit") {
                    NSApplication.shared.terminate(nil)
                }
                .buttonStyle(.plain)
                .font(.subheadline)
                .foregroundStyle(.secondary)
            }
            .padding(.horizontal, Theme.Spacing.lg)
            .padding(.vertical, Theme.Spacing.sm)
        }
    }
}
