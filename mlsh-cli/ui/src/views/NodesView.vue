<script setup lang="ts">
import { computed, ref } from 'vue'
import StatBlock from '@/components/StatBlock.vue'
import StatusDot from '@/components/StatusDot.vue'
import Btn from '@/components/Btn.vue'
import { useSession } from '@/composables/useSession'
import { useNodes, nodeStatus, type NodeStatus } from '@/composables/useNodes'

const { session } = useSession()
const { nodes, summary, loading, error, reload } = useNodes()

type Filter = 'all' | NodeStatus
const filter = ref<Filter>('all')

const filtered = computed(() => {
  if (filter.value === 'all') return nodes.value
  return nodes.value.filter((n) => nodeStatus(n) === filter.value)
})

const offlineCount = computed(() => nodes.value.length - summary.value.online)
</script>

<template>
  <div class="topbar">
    <div class="breadcrumb">
      <span>{{ session?.cluster ?? '—' }}</span>
      <span class="sep">/</span>
      <span class="current">Nodes</span>
    </div>
    <div class="topbar-actions">
      <Btn @click="reload">Refresh</Btn>
      <Btn variant="primary">+ Invite node</Btn>
    </div>
  </div>

  <header class="page-header">
    <h1 class="page-title">Nodes</h1>
    <p class="page-subtitle">
      <template v-if="loading && !nodes.length">Loading…</template>
      <template v-else-if="error">{{ error }}</template>
      <template v-else>
        {{ summary.total }} machines registered ·
        {{ summary.online }} online · {{ offlineCount }} offline
      </template>
    </p>
  </header>

  <div class="stats">
    <StatBlock
      label="Online"
      :value="summary.online"
      :unit="`/${summary.total}`"
      accent
    />
    <StatBlock label="Offline" :value="offlineCount" />
    <StatBlock label="Cluster" :value="session?.cluster ?? '—'" />
    <StatBlock label="Roles" :value="session?.roles?.join(' · ') ?? '—'" />
  </div>

  <div class="section-header">
    <div class="section-title">All nodes</div>
    <div class="filters">
      <button
        v-for="f in (['all', 'online', 'offline'] as Filter[])"
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
      <div>Role</div>
      <div>Admission</div>
      <div>Node ID</div>
      <div></div>
    </div>
    <div v-if="!filtered.length && !loading" class="empty">
      No nodes match this filter.
    </div>
    <div v-for="node in filtered" :key="node.node_id" class="row">
      <div class="node-name">
        <StatusDot :state="nodeStatus(node)" />
        <div class="node-meta">
          <span class="node-hostname">{{ node.display_name || node.node_id.slice(0, 8) }}</span>
          <span class="node-tag">{{ nodeStatus(node) }}</span>
        </div>
      </div>
      <div class="ip">{{ node.overlay_ip }}</div>
      <div class="role">{{ node.role }}</div>
      <div class="cert" :class="{ ok: node.has_admission_cert }">
        {{ node.has_admission_cert ? 'signed' : 'pending' }}
      </div>
      <div class="ip">{{ node.node_id.slice(0, 12) }}…</div>
      <div class="row-action">⋯</div>
    </div>
  </div>

  <div class="footer-note">
    cluster {{ session?.cluster ?? '—' }} · {{ nodes.length }} nodes ·
    <span v-if="loading">refreshing…</span>
    <span v-else>up to date</span>
  </div>
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
  grid-template-columns: 1fr 140px 100px 110px 160px 60px;
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

.empty {
  padding: var(--space-8) var(--space-5);
  text-align: center;
  color: var(--muted-2);
  font-family: var(--font-mono);
  font-size: 13px;
}

.node-name { display: flex; align-items: center; gap: var(--space-3); }
.node-meta { display: flex; flex-direction: column; }
.node-hostname { font-weight: 500; }
.node-tag { font-size: 11px; color: var(--muted-2); font-family: var(--font-mono); }
.ip { font-family: var(--font-mono); font-size: 13px; color: var(--muted); }
.role { font-size: var(--text-sm); color: var(--muted); text-transform: capitalize; }
.cert {
  font-family: var(--font-mono);
  font-size: 12px;
  color: var(--muted-2);
}
.cert.ok { color: var(--green); }
.row-action { color: var(--muted-2); cursor: pointer; text-align: right; }
.row-action:hover { color: var(--text); }

.footer-note {
  margin-top: var(--space-6);
  font-size: var(--text-sm);
  color: var(--muted-2);
  font-family: var(--font-mono);
}
</style>
