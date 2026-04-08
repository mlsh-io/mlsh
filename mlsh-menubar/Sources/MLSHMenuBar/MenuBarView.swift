import SwiftUI

struct MenuBarView: View {
    @ObservedObject var appState: AppState

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            HeaderView(
                overallState: appState.overallState,
                statusText: appState.statusText
            )

            Divider()

            if !appState.daemonReachable {
                DaemonDownView(onRetry: { appState.retryConnection() })
            } else {
                TunnelSectionView(appState: appState)
            }

            Divider()

            FooterView(
                version: appState.appVersion,
                lastMessage: appState.lastMessage,
                onOpenConfig: { appState.openConfigFolder() }
            )
        }
        .frame(width: Theme.Dimensions.popoverWidth)
        .animation(Theme.Anim.stateChange, value: appState.lastMessage != nil)
    }
}
