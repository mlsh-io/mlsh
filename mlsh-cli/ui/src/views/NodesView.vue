<script setup lang="ts">
import { computed, ref } from 'vue'
import StatBlock from '@/components/StatBlock.vue'
import StatusDot from '@/components/StatusDot.vue'
import Btn from '@/components/Btn.vue'
import { useNodes, type NodeStatus } from '@/composables/useNodes'

const { nodes } = useNodes()

type Filter = 'all' | NodeStatus
const filter = ref<Filter>('all')

const filtered = computed(() =>
  filter.value === 'all' ? nodes.value : nodes.value.filter(n => n.status === filter.value),
)

const summary = computed(() => {
  const online = nodes.value.filter(n => n.status === 'online').length
  const relayed = nodes.value.filter(n => n.status === 'relayed').length
  return { online, relayed, total: nodes.value.length }
})

function latencyClass(ms: number | null): string {
  if (ms === null) return ''
  if (ms < 30) return 'good'
  if (ms < 100) return 'warn'
  return 'bad'
}
</script>

<template>
  <div class="topbar">
    <div class="breadcrumb">
      <span>orbital-prod</span>
      <span class="sep">/</span>
      <span class="current">Nodes</span>
    </div>
    <div class="topbar-actions">
      <Btn>Invite peer</Btn>
      <Btn variant="primary">+ Add node</Btn>
    </div>
  </div>

  <header class="page-header">
    <h1 class="page-title">Nodes</h1>
    <p class="page-subtitle">
      {{ summary.total }} machines across the overlay ·
      {{ summary.online }} reachable directly · {{ summary.relayed }} relayed
    </p>
  </header>

  <div class="stats">
    <StatBlock
      label="Online"
      :value="summary.online"
      :unit="`/${summary.total}`"
      delta="+2 last hour"
      accent
    />
    <StatBlock label="Tunnels active" value="31" delta="28 direct · 3 relayed" />
    <StatBlock label="Throughput" value="142" unit="MB/s" delta="peak 318 MB/s" />
    <StatBlock label="P50 latency" value="8" unit="ms" delta="P99 · 47 ms" />
  </div>

  <div class="section-header">
    <div class="section-title">All nodes</div>
    <div class="filters">
      <button
        v-for="f in ['all', 'online', 'relayed', 'offline'] as Filter[]"
        :key="f"
        class="chip"
        :class="{ active: filter === f }"
        @click="filter = f"
      >
        {{ f === 'all' ? 'All' : f.charAt(0).toUpperCase() + f.slice(1) }}
      </button>
    </div>
  </div>

  <div class="table">
    <div class="row head">
      <div>Name</div>
      <div>Overlay IP</div>
      <div>Endpoint</div>
      <div>Platform</div>
      <div>Latency</div>
      <div></div>
    </div>
    <div v-for="node in filtered" :key="node.id" class="row">
      <div class="node-name">
        <StatusDot :state="node.status" />
        <div class="node-meta">
          <span class="node-hostname">{{ node.hostname }}</span>
          <span class="node-tag">{{ node.tags.join(' ') }}</span>
        </div>
      </div>
      <div class="ip">{{ node.overlayIp }}</div>
      <div class="ip">{{ node.endpoint }}</div>
      <div class="platform">{{ node.platform }}</div>
      <div class="latency" :class="latencyClass(node.latencyMs)">
        {{ node.latencyMs !== null ? `${node.latencyMs} ms` : '—' }}
      </div>
      <div class="row-action">⋯</div>
    </div>
  </div>

  <div class="footer-note">orbital-prod · cluster-id 9f3e…d2cf · last sync 12s ago</div>
</template>

<style scoped>
.topbar {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: var(--space-8);
}
.breadcrumb { color: var(--muted); font-size: 13px; }
.breadcrumb .sep { color: var(--muted-2); margin: 0 var(--space-2); }
.breadcrumb .current { color: var(--text); }
.topbar-actions { display: flex; gap: var(--space-2); }

.page-header { margin-bottom: var(--space-8); }
.page-title {
  font-size: var(--text-2xl);
  font-weight: 600;
  letter-spacing: var(--tracking-tight);
  margin-bottom: 6px;
}
.page-subtitle { color: var(--muted); font-size: var(--text-base); }

.stats {
  display: grid;
  grid-template-columns: repeat(4, 1fr);
  gap: var(--space-4);
  margin-bottom: var(--space-8);
}

.section-header {
  display: flex;
  justify-content: space-between;
  align-items: baseline;
  margin-bottom: 14px;
}
.section-title { font-size: var(--text-md); font-weight: 600; }
.filters { display: flex; gap: 6px; }
.chip {
  padding: 4px 10px;
  border-radius: var(--radius-pill);
  font-size: var(--text-sm);
  color: var(--muted);
  border: 1px solid var(--border);
  background: transparent;
}
.chip.active {
  color: var(--gold);
  border-color: rgba(201, 169, 97, 0.3);
  background: rgba(201, 169, 97, 0.06);
}

.table {
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: var(--radius-lg);
  overflow: hidden;
}
.row {
  display: grid;
  grid-template-columns: 1fr 140px 200px 130px 100px 60px;
  gap: var(--space-4);
  padding: 14px var(--space-5);
  align-items: center;
  border-bottom: 1px solid var(--border);
  transition: background var(--transition-fast);
}
.row:last-child { border-bottom: none; }
.row:hover:not(.head) { background: var(--surface-2); }
.row.head {
  font-size: var(--text-xs);
  letter-spacing: var(--tracking-uppercase);
  text-transform: uppercase;
  color: var(--muted-2);
  font-weight: 500;
}

.node-name { display: flex; align-items: center; gap: var(--space-3); }
.node-meta { display: flex; flex-direction: column; }
.node-hostname { font-weight: 500; }
.node-tag { font-size: 11px; color: var(--muted-2); font-family: var(--font-mono); }
.ip { font-family: var(--font-mono); font-size: 13px; color: var(--muted); }
.platform { font-size: var(--text-sm); color: var(--muted); }
.latency { font-family: var(--font-mono); font-size: 13px; color: var(--muted-2); }
.latency.good { color: var(--green); }
.latency.warn { color: var(--amber); }
.latency.bad { color: var(--red); }
.row-action { color: var(--muted-2); cursor: pointer; text-align: right; }
.row-action:hover { color: var(--text); }

.footer-note {
  margin-top: var(--space-6);
  font-size: var(--text-sm);
  color: var(--muted-2);
  font-family: var(--font-mono);
}
</style>
