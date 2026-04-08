import Foundation

// MARK: - Client → Daemon

/// Requests sent from the menu bar app to mlshtund.
/// JSON: `{"type":"connect","cluster":"name"}`, `{"type":"disconnect","cluster":"name"}`, `{"type":"status"}`
enum DaemonRequest: Encodable {
    case connect(cluster: String)
    case disconnect(cluster: String)
    case status

    private enum CodingKeys: String, CodingKey {
        case type
        case cluster
    }

    func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        switch self {
        case .connect(let cluster):
            try container.encode("connect", forKey: .type)
            try container.encode(cluster, forKey: .cluster)
        case .disconnect(let cluster):
            try container.encode("disconnect", forKey: .type)
            try container.encode(cluster, forKey: .cluster)
        case .status:
            try container.encode("status", forKey: .type)
        }
    }
}

// MARK: - Daemon → Client

/// Tagged union response from mlshtund.
enum DaemonResponse: Decodable {
    case ok(message: String?)
    case error(code: String, message: String)
    case status(tunnels: [TunnelStatusDTO])

    private enum CodingKeys: String, CodingKey {
        case type
        case message
        case code
        case tunnels
    }

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        let type = try container.decode(String.self, forKey: .type)
        switch type {
        case "ok":
            let message = try container.decodeIfPresent(String.self, forKey: .message)
            self = .ok(message: message)
        case "error":
            let code = try container.decode(String.self, forKey: .code)
            let message = try container.decode(String.self, forKey: .message)
            self = .error(code: code, message: message)
        case "status":
            let tunnels = try container.decode([TunnelStatusDTO].self, forKey: .tunnels)
            self = .status(tunnels: tunnels)
        default:
            throw DecodingError.dataCorruptedError(
                forKey: .type, in: container,
                debugDescription: "Unknown response type: \(type)"
            )
        }
    }
}

// MARK: - Tunnel State

enum TunnelState: String, Codable {
    case disconnected
    case connecting
    case connected
    case reconnecting
}

// MARK: - Tunnel Status

struct TunnelStatusDTO: Codable, Identifiable {
    let cluster: String
    let state: TunnelState
    let transport: String?
    let overlayIp: String?
    let uptimeSecs: UInt64?
    let bytesTx: UInt64
    let bytesRx: UInt64
    let lastError: String?

    var id: String { cluster }

    private enum CodingKeys: String, CodingKey {
        case cluster, state, transport
        case overlayIp = "overlay_ip"
        case uptimeSecs = "uptime_secs"
        case bytesTx = "bytes_tx"
        case bytesRx = "bytes_rx"
        case lastError = "last_error"
    }
}
