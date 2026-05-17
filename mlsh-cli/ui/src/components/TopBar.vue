<script setup lang="ts">
import BrandMark from './BrandMark.vue'
import { useCluster } from '@/composables/useCluster'
import { useDrawer } from '@/composables/useDrawer'

const { cluster } = useCluster()
const { toggle } = useDrawer()
</script>

<template>
  <header class="topbar-mobile">
    <button type="button" class="burger" aria-label="Open navigation" @click="toggle">
      <svg viewBox="0 0 24 24" width="22" height="22" fill="none" stroke="currentColor" stroke-width="1.8">
        <path d="M4 6h16M4 12h16M4 18h16" stroke-linecap="round" />
      </svg>
    </button>
    <div class="brand">
      <span class="mark"><BrandMark /></span>
      <span class="name">mlsh</span>
    </div>
    <div class="cluster">{{ cluster?.name ?? '—' }}</div>
  </header>
</template>

<style scoped>
.topbar-mobile {
  display: none;
  align-items: center;
  gap: var(--space-3);
  padding: var(--space-3) var(--space-4);
  background: var(--bg);
  border-bottom: 1px solid var(--border);
  position: sticky;
  top: 0;
  z-index: 30;
}
.burger {
  display: grid;
  place-items: center;
  background: transparent;
  border: 1px solid var(--border);
  color: var(--text);
  padding: 6px;
  border-radius: var(--radius);
  cursor: pointer;
}
.burger:hover { border-color: var(--gold); }
.brand { display: flex; align-items: center; gap: 8px; }
.mark { color: var(--gold); display: grid; place-items: center; }
.name { font-weight: 600; letter-spacing: var(--tracking-tight); }
.cluster {
  margin-left: auto;
  font-family: var(--font-mono);
  font-size: var(--text-sm);
  color: var(--muted);
}

@media (max-width: 640px) {
  .topbar-mobile { display: flex; }
}
</style>
