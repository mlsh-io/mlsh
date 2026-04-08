import SwiftUI
import AppKit

struct TunnelRowView: View {
    let tunnel: TunnelStatusDTO
    let isLoading: Bool
    let copiedIP: String?
    let onDisconnect: () -> Void
    let onCopyIP: (String) -> Void

    @State private var isPulsing = false

    var body: some View {
        HStack(spacing: Theme.Spacing.md) {
            statusDot

            VStack(alignment: .leading, spacing: Theme.Spacing.xxs) {
                Text(tunnel.cluster)
                    .font(.subheadline)
                    .fontWeight(.medium)

                metadataRow

                if tunnel.bytesTx > 0 || tunnel.bytesRx > 0 {
                    trafficRow
                }

                if let error = tunnel.lastError {
                    Label(error, systemImage: "exclamationmark.circle")
                        .font(.caption2)
                        .foregroundStyle(.red)
                        .lineLimit(2)
                }
            }

            Spacer()

            actionButton
        }
        .padding(.horizontal, Theme.Spacing.lg)
        .padding(.vertical, Theme.Spacing.sm)
        .hoverableRow()
    }

    // MARK: - Status dot

    private var statusDot: some View {
        Circle()
            .fill(stateColor)
            .frame(width: Theme.Dimensions.statusDotSize,
                   height: Theme.Dimensions.statusDotSize)
            .opacity(shouldPulse ? (isPulsing ? 0.3 : 1.0) : 1.0)
            .onAppear {
                if shouldPulse { isPulsing = true }
            }
            .animation(
                shouldPulse
                    ? .easeInOut(duration: 1.0).repeatForever(autoreverses: true)
                    : .default,
                value: isPulsing
            )
    }

    private var shouldPulse: Bool {
        tunnel.state == .connecting || tunnel.state == .reconnecting
    }

    private var stateColor: Color {
        switch tunnel.state {
        case .connected: return Theme.Colors.connected
        case .connecting, .reconnecting: return Theme.Colors.partial
        case .disconnected: return Theme.Colors.disconnected
        }
    }

    // MARK: - Metadata

    private var metadataRow: some View {
        HStack(spacing: Theme.Spacing.sm) {
            if let ip = tunnel.overlayIp {
                ipLabel(ip)
            }
            if let transport = tunnel.transport {
                transportBadge(transport)
            }
            if let uptime = tunnel.uptimeSecs {
                Label(formatUptime(uptime), systemImage: "clock")
                    .lineLimit(1)
                    .fixedSize()
            }
        }
        .font(.caption)
        .foregroundStyle(.secondary)
    }

    private func ipLabel(_ ip: String) -> some View {
        HStack(spacing: 2) {
            if copiedIP == ip {
                Label("Copied", systemImage: "checkmark")
                    .foregroundStyle(Theme.Colors.connected)
                    .transition(.opacity)
            } else {
                Label(ip, systemImage: "network")
            }
        }
        .lineLimit(1)
        .fixedSize()
        .onTapGesture { onCopyIP(ip) }
        .help("Click to copy IP")
    }

    private func transportBadge(_ transport: String) -> some View {
        Text(transport)
            .font(.caption2)
            .padding(.horizontal, Theme.Spacing.xs)
            .padding(.vertical, 1)
            .background(
                Capsule().fill(Theme.Colors.transportBadge)
            )
            .lineLimit(1)
            .fixedSize()
    }

    // MARK: - Traffic

    private var trafficRow: some View {
        HStack(spacing: Theme.Spacing.sm) {
            Label(formatBytes(tunnel.bytesTx), systemImage: "arrow.up")
                .foregroundStyle(.green.opacity(0.8))
            Label(formatBytes(tunnel.bytesRx), systemImage: "arrow.down")
                .foregroundStyle(.blue.opacity(0.8))
        }
        .font(.caption2)
    }

    // MARK: - Action button

    @ViewBuilder
    private var actionButton: some View {
        if isLoading {
            ProgressView()
                .controlSize(.small)
                .frame(width: Theme.Dimensions.iconButtonSize,
                       height: Theme.Dimensions.iconButtonSize)
        } else {
            Button(action: onDisconnect) {
                Image(systemName: "xmark.circle")
                    .font(.body)
                    .foregroundStyle(.secondary)
            }
            .buttonStyle(.plain)
            .help("Disconnect")
            .frame(width: Theme.Dimensions.iconButtonSize,
                   height: Theme.Dimensions.iconButtonSize)
        }
    }
}
