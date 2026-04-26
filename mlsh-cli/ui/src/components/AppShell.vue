<script setup lang="ts">
import SideNav from './SideNav.vue'
</script>

<template>
  <div class="shell">
    <SideNav />
    <main class="main">
      <slot />
    </main>
  </div>
</template>

<style scoped>
.shell {
  display: grid;
  grid-template-columns: 240px 1fr;
  min-height: 100vh;
}
.main {
  padding: var(--space-8) var(--space-12);
  max-width: 1280px;
}
</style>
