import { createRouter, createWebHistory } from 'vue-router'

export const router = createRouter({
  history: createWebHistory(),
  routes: [
    { path: '/', redirect: '/nodes' },
    {
      path: '/nodes',
      name: 'nodes',
      component: () => import('@/views/NodesView.vue'),
    },
    {
      path: '/preferences',
      name: 'preferences',
      component: () => import('@/views/PreferencesView.vue'),
    },
  ],
})
