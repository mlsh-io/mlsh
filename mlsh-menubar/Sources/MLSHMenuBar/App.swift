import SwiftUI

@main
struct MLSHMenuBarApp: App {
    @StateObject private var appState = AppState()

    var body: some Scene {
        MenuBarExtra {
            MenuBarView(appState: appState)
                .onAppear {
                    appState.startPolling()
                }
        } label: {
            MenuBarIcon(state: appState.overallState)
        }
        .menuBarExtraStyle(.window)
    }
}
