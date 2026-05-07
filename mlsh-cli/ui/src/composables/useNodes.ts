import { computed, ref } from 'vue'
import { api } from '@/api/client'
import type { NodeInfo } from '@/api/types'

export type NodeStatus = 'online' | 'offline'

const nodes = ref<NodeInfo[]>([])
const loading = ref(false)
const error = ref<string | null>(null)
let inflight: Promise<void> | null = null

async function load(): Promise<void> {
  loading.value = true
  error.value = null
  try {
    nodes.value = await api.listNodes()
  } catch (e) {
    error.value = (e as Error).message
  } finally {
    loading.value = false
  }
}

export function useNodes() {
  if (!nodes.value.length && !inflight) {
    inflight = load().finally(() => {
      inflight = null
    })
  }

  const summary = computed(() => {
    const online = nodes.value.filter((n) => n.online).length
    return { online, total: nodes.value.length }
  })

  return { nodes, summary, loading, error, reload: load }
}

export function nodeStatus(node: NodeInfo): NodeStatus {
  return node.online ? 'online' : 'offline'
}
