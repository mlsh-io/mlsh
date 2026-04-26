// Mirrors mlsh_protocol::types::NodeInfo and the responses served by
// mlsh-cli/src/control/server.rs. Keep field names in sync with the
// `serde` representation on the Rust side.

export interface NodeInfo {
  node_id: string
  overlay_ip: string
  role: string
  online: boolean
  has_admission_cert: boolean
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
