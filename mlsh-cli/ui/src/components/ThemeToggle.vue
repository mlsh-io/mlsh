<script setup lang="ts">
import { useTheme, type ThemeMode } from '@/composables/useTheme'

const { mode } = useTheme()

const options: { value: ThemeMode; label: string; title: string }[] = [
  { value: 'auto', label: 'Auto', title: 'Follow system preference' },
  { value: 'light', label: 'Light', title: 'Light theme' },
  { value: 'dark', label: 'Dark', title: 'Dark theme' },
]
</script>

<template>
  <div class="theme-toggle" role="radiogroup" aria-label="Theme">
    <button
      v-for="opt in options"
      :key="opt.value"
      type="button"
      role="radio"
      :aria-checked="mode === opt.value"
      :class="{ active: mode === opt.value }"
      :title="opt.title"
      @click="mode = opt.value"
    >
      {{ opt.label }}
    </button>
  </div>
</template>

<style scoped>
.theme-toggle {
  display: inline-flex;
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: var(--radius);
  padding: 2px;
  width: 100%;
}
button {
  flex: 1;
  padding: 4px 6px;
  border-radius: var(--radius-sm);
  font-size: 11px;
  font-family: var(--font-mono);
  letter-spacing: 0.04em;
  color: var(--muted);
  transition: color var(--transition-fast), background var(--transition-fast);
}
button:hover { color: var(--text); }
button.active {
  background: var(--bg);
  color: var(--gold);
}
</style>
