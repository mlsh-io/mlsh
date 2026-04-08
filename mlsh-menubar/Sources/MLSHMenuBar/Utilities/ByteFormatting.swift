import Foundation

func formatBytes(_ bytes: UInt64) -> String {
    let units: [(String, Double)] = [
        ("GB", 1024 * 1024 * 1024),
        ("MB", 1024 * 1024),
        ("KB", 1024),
    ]
    for (unit, threshold) in units {
        if Double(bytes) >= threshold {
            return String(format: "%.1f %@", Double(bytes) / threshold, unit)
        }
    }
    return "\(bytes) B"
}

func formatUptime(_ seconds: UInt64) -> String {
    if seconds < 60 {
        return "\(seconds)s"
    } else if seconds < 3600 {
        return "\(seconds / 60)m \(seconds % 60)s"
    } else {
        let hours = seconds / 3600
        let mins = (seconds % 3600) / 60
        return "\(hours)h \(mins)m"
    }
}
