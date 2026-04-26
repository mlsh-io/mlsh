import { computed, ref, watch } from 'vue'
import { api } from '@/api/client'
import type { NodeInfo } from '@/api/types'
import { useSession } from './useSession'

export type NodeStatus = 'online' | 'offline'

export function useNodes() {
  const { session } = useSession()
  const nodes = ref<NodeInfo[]>([])
  const loading = ref(false)
  const error = ref<string | null>(null)

  async function reload(): Promise<void> {
    const cluster = session.value?.cluster
    if (!cluster) return
    loading.value = true
    error.value = null
    try {
      nodes.value = await api.listNodes(cluster)
    } catch (e) {
      error.value = (e as Error).message
    } finally {
      loading.value = false
    }
  }

  watch(
    () => session.value?.cluster,
    (cluster) => {
      if (cluster) reload()
    },
    { immediate: true },
  )

  const summary = computed(() => {
    const online = nodes.value.filter((n) => n.online).length
    return { online, total: nodes.value.length }
  })

  return { nodes, summary, loading, error, reload }
}

export function nodeStatus(node: NodeInfo): NodeStatus {
  return node.online ? 'online' : 'offline'
}
