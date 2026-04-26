<script setup lang="ts">
defineProps<{ state: 'online' | 'relayed' | 'offline' }>()
</script>

<template>
  <span class="dot" :class="state" />
</template>

<style scoped>
.dot {
  display: inline-block;
  width: 8px;
  height: 8px;
  border-radius: 50%;
  flex-shrink: 0;
}
.online {
  background: var(--green);
  box-shadow: var(--glow-green);
}
.relayed {
  background: var(--amber);
  box-shadow: var(--glow-amber);
}
.offline {
  background: var(--muted-2);
}
</style>
