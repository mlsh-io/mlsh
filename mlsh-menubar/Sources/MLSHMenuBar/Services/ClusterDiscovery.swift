import Foundation

/// Discovers available cluster names from ~/.config/mlsh/clusters/*.toml
enum ClusterDiscovery {
    static func availableClusters() -> [String] {
        let home = FileManager.default.homeDirectoryForCurrentUser
        let clustersDir = home.appendingPathComponent(".config/mlsh/clusters")

        guard let entries = try? FileManager.default.contentsOfDirectory(
            at: clustersDir,
            includingPropertiesForKeys: nil
        ) else {
            return []
        }

        return entries
            .filter { $0.pathExtension == "toml" }
            .map { $0.deletingPathExtension().lastPathComponent }
            .sorted()
    }
}
