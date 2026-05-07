import type {
  BootstrapStatus,
  Cluster,
  ClusterExpose,
  DeviceFlowStart,
  ManagedUser,
  NodeInfo,
  SessionUser,
  TotpEnrollment,
  WebauthnCredential,
} from './types'

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(path, {
    ...init,
    headers: { accept: 'application/json', ...(init?.headers ?? {}) },
  })
  if (!res.ok) {
    // Read the body once as text, then try to parse it as JSON. Calling
    // both res.json() and res.text() on the same Response throws
    // "Body has already been consumed" on the second call.
    const raw = await res.text()
    let detail = raw
    if (raw) {
      try {
        const body = JSON.parse(raw)
        detail = body.error ?? body.message ?? raw
      } catch {
        // not JSON — keep the raw text
      }
    }
    throw new Error(`${res.status} ${res.statusText}${detail ? ` — ${detail}` : ''}`)
  }
  if (res.status === 204 || res.headers.get('content-length') === '0') {
    return undefined as T
  }
  const text = await res.text()
  return (text ? JSON.parse(text) : (undefined as T)) as T
}

function jsonInit(method: string, body?: unknown): RequestInit {
  return {
    method,
    headers: { 'content-type': 'application/json' },
    body: body === undefined ? undefined : JSON.stringify(body),
  }
}

export const api = {
  getCluster(): Promise<Cluster> {
    return request<Cluster>('/api/v1/cluster')
  },
  getClusterExpose(): Promise<ClusterExpose> {
    return request<ClusterExpose>('/api/v1/cluster/expose')
  },
  setClusterExpose(enabled: boolean): Promise<ClusterExpose> {
    return request<ClusterExpose>('/api/v1/cluster/expose', jsonInit('PUT', { enabled }))
  },
  getCurrentUser(): Promise<SessionUser> {
    return request<SessionUser>('/api/v1/users/current')
  },
  listNodes(): Promise<NodeInfo[]> {
    return request<NodeInfo[]>('/api/v1/nodes')
  },
  revokeNode(target: string): Promise<unknown> {
    return request(`/api/v1/nodes/${encodeURIComponent(target)}`, jsonInit('DELETE'))
  },
  renameNode(target: string, displayName: string): Promise<unknown> {
    return request(
      `/api/v1/nodes/${encodeURIComponent(target)}/name`,
      jsonInit('POST', { display_name: displayName }),
    )
  },
  promoteNode(target: string, role: 'admin' | 'node'): Promise<unknown> {
    return request(
      `/api/v1/nodes/${encodeURIComponent(target)}/role`,
      jsonInit('POST', { role }),
    )
  },
  inviteNode(
    role: 'admin' | 'node',
    ttl_seconds: number,
  ): Promise<{
    token: string
    url: string
    cluster: string
    role: string
    expires_in: number
  }> {
    return request('/api/v1/invites', jsonInit('POST', { role, ttl_seconds }))
  },
  bootstrapStatus(): Promise<BootstrapStatus> {
    return request<BootstrapStatus>('/auth/bootstrap')
  },
  bootstrapCreate(email: string, password: string): Promise<SessionUser> {
    return request<SessionUser>('/auth/bootstrap', jsonInit('POST', { email, password }))
  },

  // Managed-mode device flow (mlsh.io)
  deviceStart(): Promise<DeviceFlowStart> {
    return request<DeviceFlowStart>('/auth/login/device/start', jsonInit('POST'))
  },
  /**
   * Poll once. Returns:
   *  - 'authorized' when mlsh-cloud has emitted a token (cookie now set)
   *  - 'pending'    while the user hasn't authorized yet
   *  - 'gone'       on expiry / unknown ticket
   */
  async devicePoll(ticket: string): Promise<'authorized' | 'pending' | 'gone'> {
    const res = await fetch('/auth/login/device/poll', jsonInit('POST', { ticket }))
    if (res.ok) return 'authorized'
    if (res.status === 425) return 'pending'
    return 'gone'
  },

  // Users
  listUsers(): Promise<ManagedUser[]> {
    return request<ManagedUser[]>('/api/v1/users')
  },
  createUser(email: string, password: string, must_change_password = false): Promise<ManagedUser> {
    return request<ManagedUser>(
      '/api/v1/users',
      jsonInit('POST', { email, password, must_change_password }),
    )
  },
  updateUser(
    id: string,
    body: { active: boolean; password?: string },
    mfaCode?: string,
  ): Promise<unknown> {
    const init = jsonInit('PUT', body)
    if (mfaCode) init.headers = { ...(init.headers ?? {}), 'X-MFA-Code': mfaCode }
    return request(`/api/v1/users/${encodeURIComponent(id)}`, init)
  },
  deleteUser(id: string, mfaCode?: string): Promise<unknown> {
    const init: RequestInit = { method: 'DELETE' }
    if (mfaCode) init.headers = { 'X-MFA-Code': mfaCode }
    return request(`/api/v1/users/${encodeURIComponent(id)}`, init)
  },

  // Session (caller's own)
  login(email: string, password: string, totp_code?: string): Promise<SessionUser> {
    return request<SessionUser>(
      '/auth/login',
      jsonInit('POST', { email, password, totp_code }),
    )
  },
  logout(): Promise<unknown> {
    return request('/auth/logout', jsonInit('POST'))
  },

  // TOTP
  totpEnroll(): Promise<TotpEnrollment> {
    return request<TotpEnrollment>('/auth/totp/enroll', jsonInit('POST'))
  },
  totpVerify(code: string): Promise<unknown> {
    return request('/auth/totp/verify', jsonInit('POST', { code }))
  },
  totpDelete(): Promise<unknown> {
    return request('/auth/totp', { method: 'DELETE' })
  },

  // WebAuthn (list/delete only — full register/auth ceremony needs browser JS)
  webauthnCredentials(): Promise<WebauthnCredential[]> {
    return request<WebauthnCredential[]>('/auth/webauthn/credentials')
  },
  webauthnDelete(id: string): Promise<unknown> {
    return request(`/auth/webauthn/credentials/${encodeURIComponent(id)}`, { method: 'DELETE' })
  },
}
