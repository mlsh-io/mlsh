import SwiftUI

struct DisconnectedClusterRowView: View {
    let cluster: String
    let isLoading: Bool
    let onConnect: () -> Void

    @State private var isHoveredButton = false

    var body: some View {
        HStack(spacing: Theme.Spacing.md) {
            Circle()
                .fill(Color.secondary.opacity(0.4))
                .frame(width: Theme.Dimensions.statusDotSize,
                       height: Theme.Dimensions.statusDotSize)

            Text(cluster)
                .font(.subheadline)
                .foregroundStyle(.secondary)

            Spacer()

            if isLoading {
                ProgressView()
                    .controlSize(.small)
                    .frame(width: Theme.Dimensions.iconButtonSize,
                           height: Theme.Dimensions.iconButtonSize)
            } else {
                Button(action: onConnect) {
                    Image(systemName: isHoveredButton ? "plus.circle.fill" : "plus.circle")
                        .font(.body)
                        .foregroundStyle(.secondary)
                }
                .buttonStyle(.plain)
                .help("Connect")
                .frame(width: Theme.Dimensions.iconButtonSize,
                       height: Theme.Dimensions.iconButtonSize)
                .onHover { isHoveredButton = $0 }
            }
        }
        .padding(.horizontal, Theme.Spacing.lg)
        .padding(.vertical, Theme.Spacing.sm)
        .hoverableRow()
    }
}
