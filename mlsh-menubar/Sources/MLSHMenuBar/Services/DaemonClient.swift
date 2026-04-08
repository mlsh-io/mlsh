import Foundation

/// Communicates with mlshtund via its Unix domain socket using length-prefixed JSON.
/// Each request opens a fresh connection (the daemon handles one request per connection).
enum DaemonClient {

    /// Send a request to the daemon and return the response.
    /// Opens a new socket connection, sends the request, reads the response, then closes.
    static func send(_ request: DaemonRequest) async throws -> DaemonResponse {
        try await withCheckedThrowingContinuation { continuation in
            DispatchQueue.global(qos: .userInitiated).async {
                do {
                    let result = try sendSync(request)
                    continuation.resume(returning: result)
                } catch {
                    continuation.resume(throwing: error)
                }
            }
        }
    }

    /// Check if the daemon is reachable.
    static func isReachable() -> Bool {
        for path in socketPaths() {
            if FileManager.default.isReadableFile(atPath: path) {
                return true
            }
        }
        return false
    }

    // MARK: - Synchronous (runs on background queue)

    private static func sendSync(_ request: DaemonRequest) throws -> DaemonResponse {
        let fd = try connectToSocket()
        defer { close(fd) }

        // Encode request
        let json = try JSONEncoder().encode(request)
        var length = UInt32(json.count).bigEndian
        let lengthData = Data(bytes: &length, count: 4)

        // Write length prefix + JSON
        try writeAll(fd, lengthData)
        try writeAll(fd, json)

        // Read response length prefix
        let lenBuf = try readExact(fd, 4)
        let responseLength = lenBuf.withUnsafeBytes { $0.load(as: UInt32.self).bigEndian }

        guard responseLength > 0, responseLength < 1_048_576 else {
            throw DaemonError.invalidResponse
        }

        // Read response JSON
        let responseBuf = try readExact(fd, Int(responseLength))
        return try JSONDecoder().decode(DaemonResponse.self, from: responseBuf)
    }

    private static func connectToSocket() throws -> Int32 {
        let paths = socketPaths()
        var lastError: DaemonError = .notRunning

        for path in paths {
            guard FileManager.default.fileExists(atPath: path) else { continue }

            let fd = socket(AF_UNIX, SOCK_STREAM, 0)
            guard fd >= 0 else { continue }

            var addr = sockaddr_un()
            addr.sun_family = sa_family_t(AF_UNIX)

            let pathBytes = path.utf8CString
            guard pathBytes.count <= MemoryLayout.size(ofValue: addr.sun_path) else {
                close(fd)
                continue
            }

            withUnsafeMutablePointer(to: &addr.sun_path) { ptr in
                ptr.withMemoryRebound(to: CChar.self, capacity: pathBytes.count) { dst in
                    pathBytes.withUnsafeBufferPointer { src in
                        _ = memcpy(dst, src.baseAddress!, src.count)
                    }
                }
            }

            let addrLen = socklen_t(MemoryLayout<sa_family_t>.size + pathBytes.count)
            let result = withUnsafePointer(to: &addr) { ptr in
                ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sockPtr in
                    Foundation.connect(fd, sockPtr, addrLen)
                }
            }

            if result == 0 {
                return fd
            }

            lastError = .connectionFailed(path: path, errno: errno)
            close(fd)
        }

        throw lastError
    }

    private static func writeAll(_ fd: Int32, _ data: Data) throws {
        try data.withUnsafeBytes { buffer in
            guard let ptr = buffer.baseAddress else { return }
            var written = 0
            while written < data.count {
                let n = write(fd, ptr + written, data.count - written)
                if n <= 0 {
                    throw DaemonError.writeFailed
                }
                written += n
            }
        }
    }

    private static func readExact(_ fd: Int32, _ count: Int) throws -> Data {
        var buffer = Data(count: count)
        var totalRead = 0
        try buffer.withUnsafeMutableBytes { ptr in
            guard let base = ptr.baseAddress else { return }
            while totalRead < count {
                let n = read(fd, base + totalRead, count - totalRead)
                if n <= 0 {
                    throw DaemonError.readFailed
                }
                totalRead += n
            }
        }
        return buffer
    }

    private static func socketPaths() -> [String] {
        var paths = ["/var/run/mlshtund.sock"]
        let home = FileManager.default.homeDirectoryForCurrentUser.path
        paths.append("\(home)/.config/mlsh/mlshtund.sock")
        return paths
    }
}

enum DaemonError: LocalizedError {
    case notRunning
    case socketCreationFailed
    case connectionFailed(path: String, errno: Int32)
    case writeFailed
    case readFailed
    case invalidResponse

    var errorDescription: String? {
        switch self {
        case .notRunning:
            return "mlshtund is not running"
        case .socketCreationFailed:
            return "Failed to create socket"
        case .connectionFailed(let path, let err):
            return "Failed to connect to \(path): \(String(cString: strerror(err)))"
        case .writeFailed:
            return "Failed to write to daemon"
        case .readFailed:
            return "Failed to read from daemon"
        case .invalidResponse:
            return "Invalid response from daemon"
        }
    }
}
