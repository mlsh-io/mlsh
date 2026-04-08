import SwiftUI

struct HeaderView: View {
    let overallState: OverallState
    let statusText: String

    @State private var isPulsing = false

    var body: some View {
        HStack {
            Image(systemName: "server.rack")
                .font(.title2)
                .foregroundStyle(.secondary)

            VStack(alignment: .leading, spacing: Theme.Spacing.xxs) {
                Text("MLSH")
                    .font(.headline)
                Text(statusText)
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }

            Spacer()

            statusDot
        }
        .padding(.horizontal, Theme.Spacing.lg)
        .padding(.vertical, Theme.Spacing.md)
    }

    private var statusDot: some View {
        ZStack {
            Circle()
                .fill(dotColor)
                .frame(width: Theme.Dimensions.headerDotSize,
                       height: Theme.Dimensions.headerDotSize)

            // Radar-ping pulse for transitional states
            if shouldPulse {
                Circle()
                    .stroke(dotColor.opacity(0.4), lineWidth: 2)
                    .frame(width: Theme.Dimensions.headerDotSize,
                           height: Theme.Dimensions.headerDotSize)
                    .scaleEffect(isPulsing ? 2.0 : 1.0)
                    .opacity(isPulsing ? 0 : 1)
                    .onAppear { isPulsing = true }
                    .animation(Theme.Anim.pulse, value: isPulsing)
            }
        }
    }

    private var shouldPulse: Bool {
        overallState == .partial
    }

    private var dotColor: Color {
        switch overallState {
        case .connected: return Theme.Colors.connected
        case .partial: return Theme.Colors.partial
        case .disconnected: return Theme.Colors.disconnected
        case .daemonDown: return Theme.Colors.daemonDown
        }
    }
}
