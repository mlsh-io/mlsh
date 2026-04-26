<script setup lang="ts">
defineProps<{
  label: string
  value: string | number
  unit?: string
  delta?: string
  accent?: boolean
}>()
</script>

<template>
  <div class="stat" :class="{ accent }">
    <div class="label">{{ label }}</div>
    <div class="value">
      {{ value }}<span v-if="unit" class="unit">{{ unit }}</span>
    </div>
    <div v-if="delta" class="delta">{{ delta }}</div>
  </div>
</template>

<style scoped>
.stat {
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: var(--radius-lg);
  padding: 18px var(--space-5);
}
.label {
  font-size: var(--text-xs);
  letter-spacing: var(--tracking-uppercase);
  text-transform: uppercase;
  color: var(--muted-2);
  margin-bottom: var(--space-2);
}
.value {
  font-size: 26px;
  font-weight: 500;
  letter-spacing: var(--tracking-tight);
}
.unit {
  font-size: var(--text-base);
  color: var(--muted);
  margin-left: 4px;
  font-weight: 400;
}
.delta {
  font-size: var(--text-sm);
  margin-top: 6px;
  color: var(--green);
  font-family: var(--font-mono);
}
.accent .value { color: var(--gold); }
</style>
