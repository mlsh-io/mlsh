<script setup lang="ts">
import ThemeToggle from '@/components/ThemeToggle.vue'
import { useSession } from '@/composables/useSession'

const { session } = useSession()
</script>

<template>
  <div class="topbar">
    <div class="breadcrumb">
      <span>{{ session?.cluster ?? '—' }}</span>
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
</style>
