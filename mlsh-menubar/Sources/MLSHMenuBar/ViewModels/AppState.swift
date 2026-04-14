import Foundation
import Combine
import AppKit

/// Overall connection state for the menu bar icon.
enum OverallState {
    case connected     // All tunnels connected
    case partial       // Some connected, some not
    case disconnected  // No tunnels or all disconnected
    case daemonDown    // Cannot reach mlshtund
}

/// Main application state, drives the menu bar UI.
final class AppState: ObservableObject {
    @Published var tunnels: [TunnelStatusDTO] = []
    @Published var availableClusters: [String] = []
    @Published var daemonReachable: Bool = false
    @Published var lastMessage: String?
    @Published var isConnecting: Set<String> = []
    @Published var copiedIP: String?

    private var pollTask: Task<Void, Never>?
    private var messageDismissTask: Task<Void, Never>?

    let appVersion: String = {
        // Get version from the mlsh binary in the same app bundle
        guard let mlshURL = Bundle.main.url(forAuxiliaryExecutable: "mlsh") else {
            return "dev"
        }
        let process = Process()
        process.executableURL = mlshURL
        process.arguments = ["--version"]
        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = FileHandle.nullDevice
        do {
            try process.run()
            process.waitUntilExit()
            let data = pipe.fileHandleForReading.readDataToEndOfFile()
            let output = String(data: data, encoding: .utf8)?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
            // Output is typically "mlsh 0.0.4-g68c6b6c" — extract version part
            return output.hasPrefix("mlsh ") ? String(output.dropFirst(5)) : output.isEmpty ? "dev" : output
        } catch {
            return "dev"
        }
    }()

    var overallState: OverallState {
        guard daemonReachable else { return .daemonDown }
        let connectedCount = tunnels.filter { $0.state == .connected }.count
        if connectedCount == 0 { return .disconnected }
        if connectedCount == tunnels.count { return .connected }
        return .partial
    }

    /// Number of connected tunnels.
    var connectedCount: Int {
        tunnels.filter { $0.state == .connected }.count
    }

    /// Human-readable status string.
    var statusText: String {
        switch overallState {
        case .connected:
            return tunnels.count == 1 ? "Connected" : "\(tunnels.count) connected"
        case .partial:
            return "\(connectedCount) of \(tunnels.count) connected"
        case .disconnected:
            return "Disconnected"
        case .daemonDown:
            return "Daemon not running"
        }
    }

    /// Clusters from disk that don't have an active tunnel.
    var disconnectedClusters: [String] {
        let activeClusters = Set(tunnels.map(\.cluster))
        return availableClusters.filter { !activeClusters.contains($0) }
    }

    func startPolling() {
        pollTask?.cancel()
        pollTask = Task { [weak self] in
            while !Task.isCancelled {
                await self?.poll()
                try? await Task.sleep(nanoseconds: 3_000_000_000) // 3s
            }
        }
    }

    func stopPolling() {
        pollTask?.cancel()
        pollTask = nil
    }

    func connect(cluster: String) {
        isConnecting.insert(cluster)
        Task {
            do {
                let home = FileManager.default.homeDirectoryForCurrentUser
                let configDir = home.appendingPathComponent(".config/mlsh")

                let configToml = try String(
                    contentsOf: configDir.appendingPathComponent("clusters/\(cluster).toml"),
                    encoding: .utf8
                )
                let certPem = try String(
                    contentsOf: configDir.appendingPathComponent("identity/cert.pem"),
                    encoding: .utf8
                )
                let keyPem = try String(
                    contentsOf: configDir.appendingPathComponent("identity/key.pem"),
                    encoding: .utf8
                )

                let response = try await DaemonClient.send(
                    .connect(cluster: cluster, configToml: configToml, certPem: certPem, keyPem: keyPem)
                )
                await MainActor.run {
                    isConnecting.remove(cluster)
                    handleCommandResponse(response)
                }
                await poll()
            } catch {
                await MainActor.run {
                    isConnecting.remove(cluster)
                    showMessage(error.localizedDescription)
                }
            }
        }
    }

    func disconnect(cluster: String) {
        isConnecting.insert(cluster)
        Task {
            do {
                let response = try await DaemonClient.send(.disconnect(cluster: cluster))
                await MainActor.run {
                    isConnecting.remove(cluster)
                    handleCommandResponse(response)
                }
                await poll()
            } catch {
                await MainActor.run {
                    isConnecting.remove(cluster)
                    showMessage(error.localizedDescription)
                }
            }
        }
    }

    func copyIP(_ ip: String) {
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(ip, forType: .string)
        copiedIP = ip
        Task { @MainActor in
            try? await Task.sleep(nanoseconds: 1_500_000_000)
            if copiedIP == ip { copiedIP = nil }
        }
    }

    func openConfigFolder() {
        let home = FileManager.default.homeDirectoryForCurrentUser
        let url = home.appendingPathComponent(".config/mlsh")
        NSWorkspace.shared.open(url)
    }

    func retryConnection() {
        Task { await poll() }
    }

    private func poll() async {
        let clusters = ClusterDiscovery.availableClusters()

        do {
            let response = try await DaemonClient.send(.status)
            await MainActor.run {
                availableClusters = clusters
                switch response {
                case .status(let newTunnels):
                    tunnels = newTunnels
                    daemonReachable = true
                    lastMessage = nil
                case .error(_, let message):
                    showMessage(message)
                    daemonReachable = true
                case .ok:
                    daemonReachable = true
                }
            }
        } catch {
            await MainActor.run {
                availableClusters = clusters
                daemonReachable = false
                tunnels = []
            }
        }
    }

    private func handleCommandResponse(_ response: DaemonResponse) {
        switch response {
        case .ok(let message):
            if let message { showMessage(message) }
        case .error(_, let message):
            showMessage(message)
        case .status:
            break
        }
    }

    private func showMessage(_ text: String) {
        lastMessage = text
        messageDismissTask?.cancel()
        messageDismissTask = Task { @MainActor [weak self] in
            try? await Task.sleep(nanoseconds: 5_000_000_000)
            if !Task.isCancelled { self?.lastMessage = nil }
        }
    }
}
