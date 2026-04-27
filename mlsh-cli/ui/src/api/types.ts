// Mirrors mlsh_protocol::types::NodeInfo and the responses served by
// mlsh-cli/src/control/server.rs. Keep field names in sync with the
// `serde` representation on the Rust side.

export interface NodeInfo {
  node_id: string
  overlay_ip: string
  role: string
  online: boolean
  display_name: string
}

export interface WhoAmI {
  cluster: string
  roles: string[]
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

export interface SessionView {
  id: string
  created_at: string
  expires_at: string
  revoked: boolean
  current: boolean
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
