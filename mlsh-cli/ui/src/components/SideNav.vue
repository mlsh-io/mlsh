<script setup lang="ts">
import { computed } from 'vue'
import { RouterLink } from 'vue-router'
import BrandMark from './BrandMark.vue'
import { useSession } from '@/composables/useSession'
import { useNodes } from '@/composables/useNodes'

interface NavItem {
  to: string
  label: string
  icon: 'nodes' | 'prefs'
  count?: number
}

const { session } = useSession()
const { nodes } = useNodes()

const network = computed<NavItem[]>(() => [
  { to: '/nodes', label: 'Nodes', icon: 'nodes', count: nodes.value.length || undefined },
])

const settings: NavItem[] = [
  { to: '/preferences', label: 'Preferences', icon: 'prefs' },
]
</script>

<template>
  <aside class="sidebar">
    <div class="brand">
      <span class="brand-mark"><BrandMark /></span>
      <span class="brand-name">mlsh</span>
    </div>

    <button class="cluster-pill" type="button">
      <span class="cluster-label">Cluster</span>
      <span class="cluster-name">
        <span>{{ session?.cluster ?? '—' }}</span>
        <span class="chev">⌄</span>
      </span>
    </button>

    <div class="nav-section">Network</div>
    <RouterLink v-for="item in network" :key="item.to" :to="item.to" class="nav-item">
      <span class="icon"><NavIcon :name="item.icon" /></span>
      <span>{{ item.label }}</span>
      <span v-if="item.count !== undefined" class="count">{{ item.count }}</span>
    </RouterLink>

    <div class="nav-section">Settings</div>
    <RouterLink v-for="item in settings" :key="item.to" :to="item.to" class="nav-item">
      <span class="icon"><NavIcon :name="item.icon" /></span>
      <span>{{ item.label }}</span>
    </RouterLink>

    <div v-if="session" class="sidebar-footer">
      <div class="role-list">{{ session.roles.join(' · ') }}</div>
    </div>
  </aside>
</template>

<script lang="ts">
import { defineComponent, h } from 'vue'

const paths: Record<string, string[]> = {
  nodes: [
    'M12 9 a3 3 0 1 0 0.001 0',
    'M5 4 a2 2 0 1 0 0.001 0', 'M19 4 a2 2 0 1 0 0.001 0',
    'M5 16 a2 2 0 1 0 0.001 0', 'M19 16 a2 2 0 1 0 0.001 0',
    'M7 7 l3 4 M17 7 l-3 4 M7 17 l3-4 M17 17 l-3-4',
  ],
  prefs: ['M12 9 a3 3 0 1 0 0.001 0', 'M12 1v3M12 20v3M4.2 4.2l2.1 2.1M17.7 17.7l2.1 2.1M1 12h3M20 12h3M4.2 19.8l2.1-2.1M17.7 6.3l2.1-2.1'],
}

const NavIcon = defineComponent({
  props: { name: { type: String, required: true } },
  setup(props) {
    return () => h('svg', {
      viewBox: '0 0 24 24', width: 16, height: 16, fill: 'none',
      stroke: 'currentColor', 'stroke-width': 1.5,
    }, paths[props.name].map(d => h('path', { d })))
  },
})

export default { components: { NavIcon } }
</script>

<style scoped>
.sidebar {
  background: var(--bg);
  border-right: 1px solid var(--border);
  padding: var(--space-6) var(--space-4);
  display: flex;
  flex-direction: column;
}

.brand {
  display: flex;
  align-items: center;
  gap: 10px;
  padding: 4px 12px 28px;
}
.brand-mark { display: grid; place-items: center; color: var(--gold); }
.brand-name { font-weight: 600; letter-spacing: var(--tracking-tight); font-size: var(--text-md); }

.cluster-pill {
  padding: 10px 12px;
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: var(--radius-md);
  margin-bottom: var(--space-6);
  width: 100%;
  text-align: left;
}
.cluster-label {
  display: block;
  font-size: 10px;
  letter-spacing: 0.1em;
  text-transform: uppercase;
  color: var(--muted-2);
  margin-bottom: 4px;
}
.cluster-name {
  font-weight: 500;
  display: flex;
  justify-content: space-between;
  align-items: center;
}
.chev { color: var(--muted-2); }

.nav-section {
  font-size: 10px;
  letter-spacing: 0.12em;
  text-transform: uppercase;
  color: var(--muted-2);
  padding: var(--space-4) var(--space-3) var(--space-2);
}

.nav-item {
  display: flex;
  align-items: center;
  gap: var(--space-3);
  padding: var(--space-2) var(--space-3);
  border-radius: var(--radius);
  color: var(--muted);
  font-size: var(--text-base);
  transition: background var(--transition-fast), color var(--transition-fast);
}
.nav-item:hover { background: var(--surface); color: var(--text); }
.nav-item.router-link-active { background: var(--surface); color: var(--gold); }
.icon { width: 16px; height: 16px; opacity: 0.85; display: grid; place-items: center; }
.count {
  margin-left: auto;
  font-size: var(--text-xs);
  color: var(--muted-2);
  font-family: var(--font-mono);
}

.sidebar-footer {
  margin-top: auto;
  padding: var(--space-3);
  border-top: 1px solid var(--border);
  display: flex;
  flex-direction: column;
  gap: var(--space-3);
}
.role-list {
  font-family: var(--font-mono);
  font-size: 11px;
  color: var(--muted-2);
  letter-spacing: 0.04em;
  text-align: center;
}
</style>
