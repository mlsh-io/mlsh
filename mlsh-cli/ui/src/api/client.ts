import type { NodeInfo, WhoAmI } from './types'

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
  return res.json() as Promise<T>
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
}
