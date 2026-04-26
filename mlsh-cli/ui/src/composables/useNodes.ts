import { ref } from 'vue'

export type NodeStatus = 'online' | 'relayed' | 'offline'

export interface Node {
  id: string
  hostname: string
  tags: string[]
  overlayIp: string
  endpoint: string
  platform: string
  latencyMs: number | null
  status: NodeStatus
}

const MOCK_NODES: Node[] = [
  {
    id: 'node_aurion',
    hostname: 'aurion',
    tags: ['tag:server', 'tag:eu-west'],
    overlayIp: '100.64.0.1',
    endpoint: 'direct · 51.15.x.x:443',
    platform: 'Linux · arm64',
    latencyMs: 3,
    status: 'online',
  },
  {
    id: 'node_mbp',
    hostname: 'nicolas-mbp',
    tags: ['tag:laptop', 'tag:trusted'],
    overlayIp: '100.64.0.2',
    endpoint: 'direct · 192.168.1.42',
    platform: 'macOS · arm64',
    latencyMs: 2,
    status: 'online',
  },
  {
    id: 'node_homelab01',
    hostname: 'homelab-01',
    tags: ['tag:homelab'],
    overlayIp: '100.64.0.3',
    endpoint: 'direct · 10.0.0.5',
    platform: 'Linux · x86_64',
    latencyMs: 11,
    status: 'online',
  },
  {
    id: 'node_edge_tokyo',
    hostname: 'edge-tokyo',
    tags: ['tag:server', 'tag:ap'],
    overlayIp: '100.64.0.7',
    endpoint: 'relayed · via signal',
    platform: 'Linux · arm64',
    latencyMs: 142,
    status: 'relayed',
  },
  {
    id: 'node_ci04',
    hostname: 'ci-runner-04',
    tags: ['tag:ci'],
    overlayIp: '100.64.0.12',
    endpoint: 'direct · 172.16.0.4',
    platform: 'Linux · x86_64',
    latencyMs: 6,
    status: 'online',
  },
  {
    id: 'node_backup',
    hostname: 'backup-nas',
    tags: ['tag:storage'],
    overlayIp: '100.64.0.18',
    endpoint: '—',
    platform: 'Linux · x86_64',
    latencyMs: null,
    status: 'offline',
  },
  {
    id: 'node_pixel',
    hostname: 'phone-pixel',
    tags: ['tag:mobile'],
    overlayIp: '100.64.0.21',
    endpoint: 'direct · 4G/LTE',
    platform: 'Android · arm64',
    latencyMs: 38,
    status: 'online',
  },
]

export function useNodes() {
  const nodes = ref<Node[]>(MOCK_NODES)
  return { nodes }
}
