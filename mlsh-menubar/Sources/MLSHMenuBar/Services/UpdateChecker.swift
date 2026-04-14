import Foundation

/// Checks GitHub Releases for a newer version of mlsh.
enum UpdateChecker {

    struct Release {
        let tag: String        // e.g. "v0.0.5"
        let version: String    // e.g. "0.0.5"
        let htmlURL: String    // GitHub release page
        let pkgURL: String?    // Direct .pkg download URL
    }

    /// Check if a newer release exists on GitHub.
    /// Returns the release info if an update is available, nil otherwise.
    static func checkForUpdate(currentVersion: String) async -> Release? {
        guard let url = URL(string: "https://api.github.com/repos/mlsh-io/mlsh/releases/latest") else {
            return nil
        }

        var request = URLRequest(url: url)
        request.setValue("mlsh-menubar", forHTTPHeaderField: "User-Agent")
        request.timeoutInterval = 10

        do {
            let (data, response) = try await URLSession.shared.data(for: request)

            guard let http = response as? HTTPURLResponse, http.statusCode == 200 else {
                return nil
            }

            guard let json = try JSONSerialization.jsonObject(with: data) as? [String: Any],
                  let tag = json["tag_name"] as? String,
                  let htmlURL = json["html_url"] as? String else {
                return nil
            }

            let remoteVersion = tag.hasPrefix("v") ? String(tag.dropFirst()) : tag

            guard isNewer(remote: remoteVersion, current: currentVersion) else {
                return nil
            }

            // Find the .pkg asset
            var pkgURL: String?
            if let assets = json["assets"] as? [[String: Any]] {
                for asset in assets {
                    if let name = asset["name"] as? String,
                       name.hasSuffix("-macos-universal.pkg"),
                       let downloadURL = asset["browser_download_url"] as? String {
                        pkgURL = downloadURL
                        break
                    }
                }
            }

            return Release(tag: tag, version: remoteVersion, htmlURL: htmlURL, pkgURL: pkgURL)
        } catch {
            return nil
        }
    }

    /// Compare semver-ish version strings. Returns true if remote > current.
    private static func isNewer(remote: String, current: String) -> Bool {
        // Strip git describe suffix (e.g. "0.0.4-2-g68c6b6c" → "0.0.4")
        let remoteParts = remote.split(separator: "-", maxSplits: 1).first.map(String.init) ?? remote
        let currentParts = current.split(separator: "-", maxSplits: 1).first.map(String.init) ?? current

        let r = remoteParts.split(separator: ".").compactMap { Int($0) }
        let c = currentParts.split(separator: ".").compactMap { Int($0) }

        for i in 0..<max(r.count, c.count) {
            let rv = i < r.count ? r[i] : 0
            let cv = i < c.count ? c[i] : 0
            if rv > cv { return true }
            if rv < cv { return false }
        }
        return false
    }
}
