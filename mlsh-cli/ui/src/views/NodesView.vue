<script setup lang="ts">
import { computed, nextTick, onBeforeUnmount, ref, watch } from 'vue'
import StatBlock from '@/components/StatBlock.vue'
import StatusDot from '@/components/StatusDot.vue'
import Btn from '@/components/Btn.vue'
import { useSession } from '@/composables/useSession'
import { useNodes, nodeStatus, type NodeStatus } from '@/composables/useNodes'
import { api } from '@/api/client'
import type { NodeInfo } from '@/api/types'

const { session } = useSession()
const { nodes, summary, loading, error, reload } = useNodes()

type Filter = 'all' | NodeStatus
const filter = ref<Filter>('all')

const filtered = computed(() => {
  if (filter.value === 'all') return nodes.value
  return nodes.value.filter((n) => nodeStatus(n) === filter.value)
})

const offlineCount = computed(() => nodes.value.length - summary.value.online)

const openMenuFor = ref<string | null>(null)
const busyNodeId = ref<string | null>(null)
const actionError = ref<string | null>(null)
const renamingNodeId = ref<string | null>(null)
const renameDraft = ref('')
const renameInputRef = ref<HTMLInputElement | null>(null)
function setRenameInputRef(el: unknown) {
  renameInputRef.value = (el as HTMLInputElement | null) ?? null
}
const confirmRevoke = ref<NodeInfo | null>(null)

function toggleMenu(nodeId: string) {
  openMenuFor.value = openMenuFor.value === nodeId ? null : nodeId
}

function closeMenu() {
  openMenuFor.value = null
}

function onDocMousedown(e: MouseEvent) {
  const target = e.target as HTMLElement | null
  if (!target) return
  if (target.closest('.row-action')) return
  closeMenu()
}

watch(openMenuFor, (open) => {
  if (open) {
    document.addEventListener('mousedown', onDocMousedown)
  } else {
    document.removeEventListener('mousedown', onDocMousedown)
  }
})

onBeforeUnmount(() => {
  document.removeEventListener('mousedown', onDocMousedown)
})

async function runAction(node: NodeInfo, action: () => Promise<unknown>) {
  closeMenu()
  busyNodeId.value = node.node_id
  actionError.value = null
  try {
    await action()
    await reload()
  } catch (e) {
    actionError.value = (e as Error).message
  } finally {
    busyNodeId.value = null
  }
}

function askRevoke(node: NodeInfo) {
  closeMenu()
  confirmRevoke.value = node
}

function cancelRevoke() {
  confirmRevoke.value = null
}

function doRevoke() {
  const node = confirmRevoke.value
  const cluster = session.value?.cluster
  confirmRevoke.value = null
  if (!node || !cluster) return
  runAction(node, () => api.revokeNode(cluster, node.node_id))
}

function startRename(node: NodeInfo) {
  closeMenu()
  renamingNodeId.value = node.node_id
  renameDraft.value = node.display_name || ''
  nextTick(() => {
    renameInputRef.value?.focus()
    renameInputRef.value?.select()
  })
}

function cancelRename() {
  renamingNodeId.value = null
  renameDraft.value = ''
}

function commitRename(node: NodeInfo) {
  const cluster = session.value?.cluster
  const trimmed = renameDraft.value.trim()
  const current = node.display_name || ''
  renamingNodeId.value = null
  if (!cluster || !trimmed || trimmed === current) return
  runAction(node, () => api.renameNode(cluster, node.node_id, trimmed))
}

function onPromote(node: NodeInfo, role: 'admin' | 'node') {
  const cluster = session.value?.cluster
  if (!cluster) return
  runAction(node, () => api.promoteNode(cluster, node.node_id, role))
}

// Invite flow
const showInvite = ref(false)
const inviteRole = ref<'admin' | 'node'>('node')
const inviteTtl = ref(3600)
const inviteResult = ref<{ token: string; cluster: string; role: string; expires_in: number } | null>(null)
const inviteBusy = ref(false)
const inviteError = ref<string | null>(null)
const copied = ref(false)

function openInvite() {
  showInvite.value = true
  inviteResult.value = null
  inviteError.value = null
  inviteRole.value = 'node'
  inviteTtl.value = 3600
  copied.value = false
}

function closeInvite() {
  showInvite.value = false
  inviteResult.value = null
  inviteError.value = null
  inviteBusy.value = false
}

async function generateInvite() {
  const cluster = session.value?.cluster
  if (!cluster) return
  inviteBusy.value = true
  inviteError.value = null
  try {
    inviteResult.value = await api.inviteNode(cluster, inviteRole.value, inviteTtl.value)
  } catch (e) {
    inviteError.value = (e as Error).message
  } finally {
    inviteBusy.value = false
  }
}

function copyJoinCmd() {
  if (!inviteResult.value) return
  const cmd = `mlsh join ${inviteResult.value.cluster} ${inviteResult.value.token}`
  navigator.clipboard.writeText(cmd).then(() => {
    copied.value = true
    setTimeout(() => { copied.value = false }, 2000)
  })
}

function formatTtl(seconds: number): string {
  if (seconds < 60) return `${seconds}s`
  if (seconds < 3600) return `${Math.round(seconds / 60)}m`
  return `${Math.round(seconds / 3600)}h`
}
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
      <Btn variant="primary" @click="openInvite">+ Invite node</Btn>
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
          <input
            v-if="renamingNodeId === node.node_id"
            :ref="setRenameInputRef"
            v-model="renameDraft"
            class="rename-input"
            @keydown.enter.prevent="commitRename(node)"
            @keydown.esc.prevent="cancelRename()"
            @blur="commitRename(node)"
          />
          <span v-else class="node-hostname">
            {{ node.display_name || node.node_id.slice(0, 8) }}
          </span>
          <span class="node-tag">{{ nodeStatus(node) }}</span>
        </div>
      </div>
      <div class="ip">{{ node.overlay_ip }}</div>
      <div class="role">{{ node.role }}</div>
      <div class="ip">{{ node.node_id.slice(0, 12) }}…</div>
      <div class="row-action">
        <button
          class="row-action-btn"
          :disabled="busyNodeId === node.node_id"
          @click.stop="toggleMenu(node.node_id)"
          :aria-label="`Actions for ${node.display_name || node.node_id}`"
        >
          <span v-if="busyNodeId === node.node_id">…</span>
          <span v-else>⋯</span>
        </button>
        <div v-if="openMenuFor === node.node_id" class="action-menu" @click.stop>
          <button class="menu-item" @click="startRename(node)">Rename…</button>
          <button
            v-if="node.role !== 'admin'"
            class="menu-item"
            @click="onPromote(node, 'admin')"
          >
            Promote to admin
          </button>
          <button
            v-if="node.role === 'admin'"
            class="menu-item"
            @click="onPromote(node, 'node')"
          >
            Demote to node
          </button>
          <button class="menu-item danger" @click="askRevoke(node)">Revoke</button>
        </div>
      </div>
    </div>
  </div>

  <div v-if="actionError" class="action-error">{{ actionError }}</div>

  <div class="footer-note">
    cluster {{ session?.cluster ?? '—' }} · {{ nodes.length }} nodes ·
    <span v-if="loading">refreshing…</span>
    <span v-else>up to date</span>
  </div>

  <!-- Invite node modal -->
  <div
    v-if="showInvite"
    class="modal-backdrop"
    @click.self="closeInvite"
    @keydown.esc="closeInvite"
  >
    <div class="modal" role="dialog" aria-modal="true">
      <h3 class="modal-title">Invite a node</h3>

      <template v-if="!inviteResult">
        <div class="invite-form">
          <label class="invite-label">Role</label>
          <div class="invite-role-group">
            <button
              class="role-chip"
              :class="{ active: inviteRole === 'node' }"
              @click="inviteRole = 'node'"
            >node</button>
            <button
              class="role-chip"
              :class="{ active: inviteRole === 'admin' }"
              @click="inviteRole = 'admin'"
            >admin</button>
          </div>

          <label class="invite-label">Expires in</label>
          <div class="invite-role-group">
            <button
              v-for="opt in [{ v: 900, l: '15m' }, { v: 3600, l: '1h' }, { v: 86400, l: '24h' }]"
              :key="opt.v"
              class="role-chip"
              :class="{ active: inviteTtl === opt.v }"
              @click="inviteTtl = opt.v"
            >{{ opt.l }}</button>
          </div>
        </div>

        <div v-if="inviteError" class="action-error" style="margin-top: var(--space-3)">{{ inviteError }}</div>

        <div class="modal-actions" style="margin-top: var(--space-5)">
          <Btn @click="closeInvite">Cancel</Btn>
          <Btn variant="primary" :disabled="inviteBusy" @click="generateInvite">
            {{ inviteBusy ? 'Generating…' : 'Generate token' }}
          </Btn>
        </div>
      </template>

      <template v-else>
        <p class="modal-body">
          Token valid for <strong>{{ formatTtl(inviteResult.expires_in) }}</strong>,
          role <span class="modal-highlight">{{ inviteResult.role }}</span>.
          Run on the new machine:
        </p>
        <div class="join-cmd">
          <code>mlsh join {{ inviteResult.cluster }} {{ inviteResult.token }}</code>
          <button class="copy-btn" @click="copyJoinCmd">{{ copied ? '✓' : 'Copy' }}</button>
        </div>
        <div class="modal-actions" style="margin-top: var(--space-5)">
          <Btn @click="closeInvite">Done</Btn>
          <Btn variant="primary" @click="() => { inviteResult = null; inviteError = null }">New invite</Btn>
        </div>
      </template>
    </div>
  </div>

  <div
    v-if="confirmRevoke"
    class="modal-backdrop"
    @click.self="cancelRevoke"
    @keydown.esc="cancelRevoke"
  >
    <div class="modal" role="dialog" aria-modal="true">
      <h3 class="modal-title">Revoke node</h3>
      <p class="modal-body">
        This removes
        <span class="modal-highlight">
          {{ confirmRevoke.display_name || confirmRevoke.node_id.slice(0, 8) }}
        </span>
        from the cluster. The node loses overlay access immediately.
      </p>
      <div class="modal-actions">
        <Btn @click="cancelRevoke">Cancel</Btn>
        <Btn variant="danger" @click="doRevoke">Revoke</Btn>
      </div>
    </div>
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
}
.row {
  display: grid;
  grid-template-columns: 1fr 140px 100px 160px 60px;
  gap: var(--space-4);
  padding: 14px var(--space-5);
  align-items: center;
  border-bottom: 1px solid var(--border);
  transition: background var(--transition-fast);
}
.row.head { border-top-left-radius: var(--radius-lg); border-top-right-radius: var(--radius-lg); }
.row:last-child {
  border-bottom: none;
  border-bottom-left-radius: var(--radius-lg);
  border-bottom-right-radius: var(--radius-lg);
}
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
.row-action { position: relative; text-align: right; }
.row-action-btn {
  background: transparent;
  border: none;
  color: var(--muted-2);
  cursor: pointer;
  padding: 4px 8px;
  font-size: 16px;
  line-height: 1;
  border-radius: var(--radius-sm);
}
.row-action-btn:hover:not(:disabled) { color: var(--text); background: var(--surface-2); }
.row-action-btn:disabled { cursor: wait; opacity: 0.5; }

.action-menu {
  position: absolute;
  right: 0;
  top: calc(100% + 4px);
  z-index: 10;
  min-width: 180px;
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: var(--radius-md);
  box-shadow: 0 8px 24px rgba(0, 0, 0, 0.4);
  padding: 4px;
  display: flex;
  flex-direction: column;
}
.menu-item {
  background: transparent;
  border: none;
  color: var(--text);
  text-align: left;
  padding: 8px 12px;
  font-size: var(--text-sm);
  cursor: pointer;
  border-radius: var(--radius-sm);
}
.menu-item:hover { background: var(--surface-2); }
.menu-item.danger { color: var(--red, #f87171); }
.menu-item.danger:hover { background: rgba(248, 113, 113, 0.1); }

.action-error {
  margin-top: var(--space-4);
  padding: var(--space-3) var(--space-4);
  border: 1px solid rgba(248, 113, 113, 0.3);
  background: rgba(248, 113, 113, 0.06);
  color: var(--red, #f87171);
  border-radius: var(--radius-md);
  font-size: var(--text-sm);
  font-family: var(--font-mono);
}

.footer-note {
  margin-top: var(--space-6);
  font-size: var(--text-sm);
  color: var(--muted-2);
  font-family: var(--font-mono);
}

.rename-input {
  background: var(--surface-2);
  border: 1px solid var(--gold);
  color: var(--text);
  font-size: var(--text-base);
  font-weight: 500;
  padding: 2px 6px;
  border-radius: var(--radius-sm);
  outline: none;
  width: 100%;
  font-family: inherit;
}
.rename-input:focus { box-shadow: 0 0 0 2px rgba(201, 169, 97, 0.2); }

.modal-backdrop {
  position: fixed;
  inset: 0;
  background: rgba(0, 0, 0, 0.6);
  backdrop-filter: blur(2px);
  display: flex;
  align-items: center;
  justify-content: center;
  z-index: 100;
}
.modal {
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: var(--radius-lg);
  padding: var(--space-6);
  min-width: 420px;
  max-width: 90vw;
  box-shadow: 0 20px 60px rgba(0, 0, 0, 0.5);
}
.modal-title {
  font-size: var(--text-md);
  font-weight: 600;
  margin: 0 0 var(--space-3);
}
.modal-body {
  color: var(--muted);
  font-size: var(--text-sm);
  line-height: 1.5;
  margin: 0 0 var(--space-5);
}
.modal-highlight {
  color: var(--text);
  font-family: var(--font-mono);
  font-weight: 500;
}
.modal-actions {
  display: flex;
  justify-content: flex-end;
  gap: var(--space-2);
}

.invite-form { display: flex; flex-direction: column; gap: var(--space-3); }
.invite-label { font-size: var(--text-sm); color: var(--muted); }
.invite-role-group { display: flex; gap: var(--space-2); }
.role-chip {
  padding: 5px 14px;
  border-radius: var(--radius-pill);
  font-size: var(--text-sm);
  color: var(--muted);
  border: 1px solid var(--border);
  background: transparent;
  cursor: pointer;
}
.role-chip.active {
  color: var(--gold);
  border-color: rgba(201, 169, 97, 0.4);
  background: rgba(201, 169, 97, 0.08);
}

.join-cmd {
  display: flex;
  align-items: center;
  gap: var(--space-3);
  background: var(--surface-2);
  border: 1px solid var(--border);
  border-radius: var(--radius-md);
  padding: var(--space-3) var(--space-4);
  margin-top: var(--space-3);
}
.join-cmd code {
  flex: 1;
  font-family: var(--font-mono);
  font-size: 13px;
  color: var(--green);
  word-break: break-all;
}
.copy-btn {
  background: transparent;
  border: 1px solid var(--border);
  color: var(--muted);
  cursor: pointer;
  padding: 4px 10px;
  border-radius: var(--radius-sm);
  font-size: var(--text-sm);
  white-space: nowrap;
}
.copy-btn:hover { color: var(--text); border-color: var(--gold); }
</style>
