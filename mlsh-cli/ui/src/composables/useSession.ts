import { ref } from 'vue'
import { api } from '@/api/client'
import type { WhoAmI } from '@/api/types'

const session = ref<WhoAmI | null>(null)
const error = ref<string | null>(null)
let inflight: Promise<void> | null = null

async function load(): Promise<void> {
  try {
    session.value = await api.whoami()
    error.value = null
  } catch (e) {
    error.value = (e as Error).message
  }
}

export function useSession() {
  if (!session.value && !inflight) {
    inflight = load().finally(() => {
      inflight = null
    })
  }
  return { session, error, reload: load }
}
