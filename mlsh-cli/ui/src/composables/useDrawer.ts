import { ref } from 'vue'

const open = ref(false)

export function useDrawer() {
  return {
    open,
    toggle: () => { open.value = !open.value },
    close: () => { open.value = false },
  }
}
