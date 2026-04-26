import { ref, watchEffect } from 'vue'

export type ThemeMode = 'auto' | 'light' | 'dark'

const STORAGE_KEY = 'mlsh.theme'

function readStored(): ThemeMode {
  const v = localStorage.getItem(STORAGE_KEY)
  return v === 'light' || v === 'dark' || v === 'auto' ? v : 'auto'
}

const mode = ref<ThemeMode>(readStored())
const media = window.matchMedia('(prefers-color-scheme: light)')

function applyTheme(): void {
  const resolved = mode.value === 'auto' ? (media.matches ? 'light' : 'dark') : mode.value
  document.documentElement.setAttribute('data-theme', resolved)
}

media.addEventListener('change', () => {
  if (mode.value === 'auto') applyTheme()
})

watchEffect(() => {
  localStorage.setItem(STORAGE_KEY, mode.value)
  applyTheme()
})

export function useTheme() {
  return { mode }
}
