import type { NodeInfo, WhoAmI } from './types'

async function request<T>(path: string): Promise<T> {
  const res = await fetch(path, { headers: { accept: 'application/json' } })
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

export const api = {
  whoami(): Promise<WhoAmI> {
    return request<WhoAmI>('/api/v1/whoami')
  },
  listNodes(cluster: string): Promise<NodeInfo[]> {
    return request<NodeInfo[]>(`/api/v1/clusters/${encodeURIComponent(cluster)}/nodes`)
  },
}
