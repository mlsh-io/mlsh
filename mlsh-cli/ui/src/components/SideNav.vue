<script setup lang="ts">
import { RouterLink } from 'vue-router'
import BrandMark from './BrandMark.vue'

interface NavItem {
  to: string
  label: string
  icon: 'nodes' | 'tunnels' | 'acls' | 'dns' | 'signal' | 'audit' | 'prefs' | 'security'
  count?: number
}

const network: NavItem[] = [
  { to: '/nodes', label: 'Nodes', icon: 'nodes', count: 14 },
  { to: '/tunnels', label: 'Tunnels', icon: 'tunnels', count: 31 },
  { to: '/acls', label: 'ACLs', icon: 'acls' },
  { to: '/dns', label: 'DNS', icon: 'dns' },
]

const infra: NavItem[] = [
  { to: '/signal', label: 'Signal Server', icon: 'signal' },
  { to: '/audit', label: 'Audit Log', icon: 'audit' },
]

const settings: NavItem[] = [
  { to: '/preferences', label: 'Preferences', icon: 'prefs' },
  { to: '/security', label: 'Security', icon: 'security' },
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
        <span>orbital-prod</span>
        <span class="chev">⌄</span>
      </span>
    </button>

    <div class="nav-section">Network</div>
    <RouterLink v-for="item in network" :key="item.to" :to="item.to" class="nav-item">
      <span class="icon"><NavIcon :name="item.icon" /></span>
      <span>{{ item.label }}</span>
      <span v-if="item.count !== undefined" class="count">{{ item.count }}</span>
    </RouterLink>

    <div class="nav-section">Infrastructure</div>
    <RouterLink v-for="item in infra" :key="item.to" :to="item.to" class="nav-item">
      <span class="icon"><NavIcon :name="item.icon" /></span>
      <span>{{ item.label }}</span>
    </RouterLink>

    <div class="nav-section">Settings</div>
    <RouterLink v-for="item in settings" :key="item.to" :to="item.to" class="nav-item">
      <span class="icon"><NavIcon :name="item.icon" /></span>
      <span>{{ item.label }}</span>
    </RouterLink>

    <div class="sidebar-footer">
      <div class="avatar" />
      <div>
        <div class="user-name">Nicolas A.</div>
        <div class="user-email">nicolas@loftorbital</div>
      </div>
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
  tunnels: ['M3 12 L9 12 M15 12 L21 12 M9 12 Q12 6 15 12 Q12 18 9 12'],
  acls: ['M12 3 L20 7 V13 C20 17 16 20 12 21 C8 20 4 17 4 13 V7 Z'],
  dns: ['M12 3 V21 M3 12 H21'],
  signal: ['M3 4 H21 V10 H3 Z M3 14 H21 V20 H3 Z'],
  audit: ['M4 6 H20 M4 12 H20 M4 18 H14'],
  prefs: ['M12 9 a3 3 0 1 0 0.001 0', 'M12 1v3M12 20v3M4.2 4.2l2.1 2.1M17.7 17.7l2.1 2.1M1 12h3M20 12h3M4.2 19.8l2.1-2.1M17.7 6.3l2.1-2.1'],
  security: ['M12 2 L4 6 V12 C4 17 8 21 12 22 C16 21 20 17 20 12 V6 Z', 'M9 12 L11 14 L15 10'],
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
  align-items: center;
  gap: 10px;
}
.avatar {
  width: 28px;
  height: 28px;
  border-radius: 50%;
  background: linear-gradient(135deg, #c9a961, #8a7340);
}
.user-name { font-size: 13px; }
.user-email { font-size: 11px; color: var(--muted-2); }
</style>
