<script setup lang="ts">
import { useRoute } from 'vue-router'
import AppShell from '@/components/AppShell.vue'

const route = useRoute()
</script>

<template>
  <router-view v-if="route.meta.bare" />
  <AppShell v-else>
    <router-view />
  </AppShell>
</template>
