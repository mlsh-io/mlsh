<script setup lang="ts">
import { onMounted, ref } from 'vue'
import ThemeToggle from '@/components/ThemeToggle.vue'
import { useCluster } from '@/composables/useCluster'
import { api } from '@/api/client'

const { cluster } = useCluster()

const exposeEnabled = ref(false)
const exposeDomain = ref('')
const exposeError = ref<string | null>(null)
const exposeBusy = ref(false)
const exposeLoaded = ref(false)

onMounted(async () => {
  try {
    const s = await api.getClusterExpose()
    exposeEnabled.value = s.enabled
    exposeDomain.value = s.domain
  } catch (e) {
    exposeError.value = (e as Error).message
  } finally {
    exposeLoaded.value = true
  }
})

async function toggleExpose(next: boolean) {
  if (exposeBusy.value) return
  exposeBusy.value = true
  exposeError.value = null
  try {
    const s = await api.setClusterExpose(next)
    exposeEnabled.value = s.enabled
    exposeDomain.value = s.domain
  } catch (e) {
    exposeError.value = (e as Error).message
  } finally {
    exposeBusy.value = false
  }
}
</script>

<template>
  <div class="topbar">
    <div class="breadcrumb">
      <span>{{ cluster?.name ?? '—' }}</span>
      <span class="sep">/</span>
      <span class="current">Preferences</span>
    </div>
  </div>

  <header class="page-header">
    <h1 class="page-title">Preferences</h1>
    <p class="page-subtitle">Local settings, stored in this browser only.</p>
  </header>

  <section class="card">
    <div class="row">
      <div class="row-info">
        <div class="row-label">Theme</div>
        <div class="row-hint">Auto follows your system preference.</div>
      </div>
      <div class="row-control"><ThemeToggle /></div>
    </div>
  </section>

  <section class="card">
    <div class="row">
      <div class="row-info">
        <div class="row-label">Expose admin UI</div>
        <div class="row-hint">
          <template v-if="exposeDomain">
            Make this control plane reachable on the public Internet at <code>{{ exposeDomain }}</code>. A Let's Encrypt certificate will be issued automatically.
          </template>
          <template v-else>
            The cluster zone is not yet known. Reconnect once to signal so the
            public domain can be derived.
          </template>
        </div>
        <div v-if="exposeError" class="row-error">{{ exposeError }}</div>
      </div>
      <div class="row-control">
        <label class="switch" :class="{ disabled: !exposeLoaded || exposeBusy || !exposeDomain }">
          <input
            type="checkbox"
            :checked="exposeEnabled"
            :disabled="!exposeLoaded || exposeBusy || !exposeDomain"
            @change="toggleExpose(($event.target as HTMLInputElement).checked)"
          />
          <span class="slider"></span>
          <span class="switch-label">{{ exposeEnabled ? 'On' : 'Off' }}</span>
        </label>
      </div>
    </div>
  </section>
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

.page-header { margin-bottom: var(--space-8); }
.page-title {
  font-size: var(--text-2xl);
  font-weight: 600;
  letter-spacing: var(--tracking-tight);
  margin-bottom: 6px;
}
.page-subtitle { color: var(--muted); font-size: var(--text-base); }

.card {
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: var(--radius-lg);
  overflow: hidden;
  margin-bottom: var(--space-5);
}
.row {
  display: grid;
  grid-template-columns: 1fr 220px;
  gap: var(--space-6);
  padding: var(--space-5);
  align-items: center;
  border-bottom: 1px solid var(--border);
}
.row:last-child { border-bottom: none; }
.row-label { font-weight: 500; }
.row-hint {
  font-size: var(--text-sm);
  color: var(--muted-2);
  margin-top: 2px;
}
.row-hint code {
  font-family: var(--font-mono);
  font-size: 12px;
  background: var(--bg);
  border: 1px solid var(--border);
  border-radius: var(--radius-sm);
  padding: 0 1px;
  color: var(--gold);
}
.row-error {
  margin-top: 6px;
  color: #ef4444;
  font-size: var(--text-sm);
  font-family: var(--font-mono);
}

.switch {
  display: inline-flex;
  align-items: center;
  gap: var(--space-3);
  cursor: pointer;
  user-select: none;
}
.switch.disabled { opacity: 0.5; cursor: not-allowed; }
.switch input { display: none; }
.slider {
  position: relative;
  width: 36px;
  height: 20px;
  background: var(--bg);
  border: 1px solid var(--border);
  border-radius: 999px;
  transition: background var(--transition-fast), border-color var(--transition-fast);
}
.slider::after {
  content: '';
  position: absolute;
  top: 1px;
  left: 1px;
  width: 16px;
  height: 16px;
  border-radius: 50%;
  background: var(--muted);
  transition: transform var(--transition-fast), background var(--transition-fast);
}
.switch input:checked + .slider {
  background: var(--bg);
  border-color: var(--gold);
}
.switch input:checked + .slider::after {
  transform: translateX(16px);
  background: var(--gold);
}
.switch-label {
  font-family: var(--font-mono);
  font-size: 11px;
  letter-spacing: 0.04em;
  color: var(--muted);
}
.switch input:checked ~ .switch-label { color: var(--gold); }
</style>
