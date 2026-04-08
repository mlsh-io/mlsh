import SwiftUI

struct TunnelSectionView: View {
    @ObservedObject var appState: AppState

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 0) {
                // Active tunnels
                if !appState.tunnels.isEmpty {
                    sectionHeader("ACTIVE TUNNELS", count: appState.tunnels.count)

                    ForEach(appState.tunnels) { tunnel in
                        TunnelRowView(
                            tunnel: tunnel,
                            isLoading: appState.isConnecting.contains(tunnel.cluster),
                            copiedIP: appState.copiedIP,
                            onDisconnect: { appState.disconnect(cluster: tunnel.cluster) },
                            onCopyIP: { appState.copyIP($0) }
                        )
                    }
                }

                // Available clusters
                if !appState.disconnectedClusters.isEmpty {
                    sectionHeader("AVAILABLE")

                    ForEach(appState.disconnectedClusters, id: \.self) { cluster in
                        DisconnectedClusterRowView(
                            cluster: cluster,
                            isLoading: appState.isConnecting.contains(cluster),
                            onConnect: { appState.connect(cluster: cluster) }
                        )
                    }
                }

                // Empty state
                if appState.tunnels.isEmpty && appState.disconnectedClusters.isEmpty {
                    EmptyStateView(onOpenFolder: { appState.openConfigFolder() })
                }
            }
        }
        .frame(maxHeight: Theme.Dimensions.maxContentHeight)
    }

    private func sectionHeader(_ title: String, count: Int? = nil) -> some View {
        HStack(spacing: Theme.Spacing.xs) {
            Text(title)
            if let count {
                Text("(\(count))")
            }
        }
        .font(.caption2)
        .fontWeight(.semibold)
        .foregroundStyle(.tertiary)
        .textCase(.uppercase)
        .padding(.horizontal, Theme.Spacing.lg)
        .padding(.top, Theme.Spacing.md)
        .padding(.bottom, Theme.Spacing.xs)
    }
}
