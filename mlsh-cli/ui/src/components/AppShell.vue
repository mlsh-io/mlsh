<script setup lang="ts">
import SideNav from './SideNav.vue'
import TopBar from './TopBar.vue'
import { useDrawer } from '@/composables/useDrawer'

const { open, close } = useDrawer()
</script>

<template>
  <div class="shell" :class="{ 'drawer-open': open }">
    <TopBar />
    <SideNav class="sidebar" />
    <div v-if="open" class="backdrop" @click="close" />
    <main class="main">
      <slot />
    </main>
  </div>
</template>

<style scoped>
.shell {
  display: grid;
  grid-template-columns: 240px 1fr;
  grid-template-areas:
    "sidebar main";
  min-height: 100vh;
}
.sidebar { grid-area: sidebar; }
.main {
  grid-area: main;
  padding: var(--space-8) var(--space-12);
  max-width: 1280px;
  min-width: 0;
}
.backdrop {
  position: fixed;
  inset: 0;
  background: rgba(0, 0, 0, 0.5);
  z-index: 40;
}

@media (max-width: 640px) {
  .shell {
    grid-template-columns: 1fr;
    grid-template-areas:
      "topbar"
      "main";
  }
  .sidebar {
    position: fixed;
    inset: 0 auto 0 0;
    width: min(280px, 85vw);
    z-index: 50;
    transform: translateX(-100%);
    transition: transform var(--transition);
  }
  .shell.drawer-open .sidebar { transform: translateX(0); }
  .main { padding: var(--space-4); }
}
</style>
