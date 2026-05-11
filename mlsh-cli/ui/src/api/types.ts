// Mirrors mlsh_protocol::types::NodeInfo and the responses served by
// mlsh-cli/src/control/server.rs. Keep field names in sync with the
// `serde` representation on the Rust side.

export interface NodeInfo {
  /** Stable node UUID. */
  id: string
  /** Mutable, human-readable name. */
  display_name: string
  /** `"node"` or `"admin"` (and the implied `"control"` superset). */
  role: string
  /** `"active"` or `"revoked"`. */
  status: string
  /** `true` when `status === "active"`. */
  online: boolean
  /** Cert fingerprint (cluster-CA-signed). */
  fingerprint: string
  /** Overlay IPv4 assigned by signal. Empty when the node is offline. */
  overlay_ip: string
  /** RFC 3339 UTC. */
  last_seen: string | null
  /** RFC 3339 UTC. */
  created_at: string
  /** Client release reported at handshake (empty when offline or pre-versioning). */
  client_version: string
}

export interface Cluster {
  /** Stable cluster UUID. */
  id: string
  /** Human-readable cluster name. */
  name: string
  /** mlsh version of the control instance serving this cluster. */
  version: string
  /** Public DNS zone (e.g. `mlsh.io`). Empty until learned from signal. */
  zone: string
}

export interface ClusterExpose {
  enabled: boolean
  domain: string
}

export interface ApiError {
  error: string
  code?: string
}

export type ClusterMode = 'self-hosted' | 'managed'

export interface BootstrapStatus {
  needed: boolean
  mode: ClusterMode | null
}

export interface SessionUser {
  id: string
  email: string
  must_change_password: boolean
}

export interface ManagedUser {
  id: string
  email: string
  source: 'local' | 'managed'
  active: boolean
  must_change_password: boolean
}

export interface TotpEnrollment {
  secret_base32: string
  otpauth_uri: string
}

export interface WebauthnCredential {
  id: string
  name: string
}

export interface DeviceFlowStart {
  ticket: string
  user_code: string
  verification_uri: string
  interval: number
}
