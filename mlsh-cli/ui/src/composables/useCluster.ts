import { ref } from 'vue'
import { api } from '@/api/client'
import type { Cluster } from '@/api/types'

const cluster = ref<Cluster | null>(null)
const error = ref<string | null>(null)
let inflight: Promise<void> | null = null

async function load(): Promise<void> {
  try {
    cluster.value = await api.getCluster()
    error.value = null
  } catch (e) {
    error.value = (e as Error).message
  }
}

export function useCluster() {
  if (!cluster.value && !inflight) {
    inflight = load().finally(() => {
      inflight = null
    })
  }
  return { cluster, error, reload: load }
}
