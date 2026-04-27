import type {
  BootstrapStatus,
  DeviceFlowStart,
  ManagedUser,
  NodeInfo,
  SessionUser,
  SessionView,
  TotpEnrollment,
  WebauthnCredential,
  WhoAmI,
} from './types'

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(path, {
    ...init,
    headers: { accept: 'application/json', ...(init?.headers ?? {}) },
  })
  if (!res.ok) {
    let detail = ''
    try {
      const body = await res.json()
      detail = body.error ?? JSON.stringify(body)
    } catch {
      detail = await res.text()
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
  whoami(): Promise<WhoAmI> {
    return request<WhoAmI>('/api/v1/whoami')
  },
  listNodes(cluster: string): Promise<NodeInfo[]> {
    return request<NodeInfo[]>(`/api/v1/clusters/${encodeURIComponent(cluster)}/nodes`)
  },
  revokeNode(cluster: string, target: string): Promise<unknown> {
    return request(
      `/api/v1/clusters/${encodeURIComponent(cluster)}/nodes/${encodeURIComponent(target)}`,
      jsonInit('DELETE'),
    )
  },
  renameNode(cluster: string, target: string, displayName: string): Promise<unknown> {
    return request(
      `/api/v1/clusters/${encodeURIComponent(cluster)}/nodes/${encodeURIComponent(target)}`,
      jsonInit('PATCH', { display_name: displayName }),
    )
  },
  promoteNode(cluster: string, target: string, role: 'admin' | 'node'): Promise<unknown> {
    return request(
      `/api/v1/clusters/${encodeURIComponent(cluster)}/nodes/${encodeURIComponent(target)}/promote`,
      jsonInit('POST', { role }),
    )
  },
  inviteNode(
    cluster: string,
    role: 'admin' | 'node',
    ttl: number,
  ): Promise<{ token: string; cluster: string; role: string; expires_in: number }> {
    return request(
      `/api/v1/clusters/${encodeURIComponent(cluster)}/invite`,
      jsonInit('POST', { role, ttl }),
    )
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
    body: { active?: boolean; password?: string },
    mfaCode?: string,
  ): Promise<unknown> {
    const init = jsonInit('PATCH', body)
    if (mfaCode) init.headers = { ...(init.headers ?? {}), 'X-MFA-Code': mfaCode }
    return request(`/api/v1/users/${encodeURIComponent(id)}`, init)
  },
  deleteUser(id: string, mfaCode?: string): Promise<unknown> {
    const init: RequestInit = { method: 'DELETE' }
    if (mfaCode) init.headers = { 'X-MFA-Code': mfaCode }
    return request(`/api/v1/users/${encodeURIComponent(id)}`, init)
  },

  // Session (caller's own)
  whoamiSession(): Promise<SessionUser> {
    return request<SessionUser>('/auth/session')
  },
  login(email: string, password: string, totp_code?: string): Promise<SessionUser> {
    return request<SessionUser>(
      '/auth/login',
      jsonInit('POST', { email, password, totp_code }),
    )
  },
  logout(): Promise<unknown> {
    return request('/auth/logout', jsonInit('POST'))
  },
  listSessions(): Promise<SessionView[]> {
    return request<SessionView[]>('/auth/sessions')
  },
  revokeSession(id: string): Promise<unknown> {
    return request(`/auth/sessions/${encodeURIComponent(id)}`, { method: 'DELETE' })
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
