<script setup lang="ts">
defineProps<{
  variant?: 'default' | 'primary' | 'ghost' | 'danger'
}>()
</script>

<template>
  <button class="btn" :class="variant ?? 'default'">
    <slot />
  </button>
</template>

<style scoped>
.btn {
  padding: var(--space-2) 14px;
  border-radius: var(--radius);
  font-size: 13px;
  font-weight: 500;
  border: 1px solid var(--border);
  background: var(--surface);
  color: var(--text);
  transition: border-color var(--transition-fast), background var(--transition-fast);
  display: inline-flex;
  align-items: center;
  gap: 6px;
}
.btn:hover { border-color: var(--border-hover); }

.primary {
  background: var(--gold);
  color: var(--gold-on);
  border-color: var(--gold);
}
.primary:hover {
  background: var(--gold-bright);
  border-color: var(--gold-bright);
}

.ghost {
  background: transparent;
  border-color: transparent;
}
.ghost:hover { background: var(--surface); }

.danger {
  color: var(--red);
  border-color: rgba(248, 113, 113, 0.25);
}
.danger:hover {
  background: rgba(248, 113, 113, 0.06);
  border-color: rgba(248, 113, 113, 0.4);
}
</style>
