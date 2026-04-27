import { createRouter, createWebHistory } from 'vue-router'
import { api } from '@/api/client'

export const router = createRouter({
  history: createWebHistory(),
  routes: [
    { path: '/', redirect: '/nodes' },
    {
      path: '/setup',
      name: 'setup',
      meta: { bare: true, public: true },
      component: () => import('@/views/BootstrapView.vue'),
    },
    {
      path: '/login',
      name: 'login',
      meta: { bare: true, public: true },
      component: () => import('@/views/LoginView.vue'),
    },
    {
      path: '/nodes',
      name: 'nodes',
      component: () => import('@/views/NodesView.vue'),
    },
    {
      path: '/users',
      name: 'users',
      component: () => import('@/views/UsersView.vue'),
    },
    {
      path: '/account',
      name: 'account',
      component: () => import('@/views/AccountView.vue'),
    },
    {
      path: '/preferences',
      name: 'preferences',
      component: () => import('@/views/PreferencesView.vue'),
    },
  ],
})

// 1. While the cluster has no admin user, force every navigation to /setup.
// 2. Once an admin exists, require an authenticated session for non-public routes.
router.beforeEach(async (to) => {
  let needed = false
  try {
    needed = (await api.bootstrapStatus()).needed
  } catch {
    return true
  }
  if (needed && to.name !== 'setup') return { name: 'setup' }
  if (!needed && to.name === 'setup') return { name: 'nodes' }

  if (to.meta.public) return true

  try {
    await api.whoami()
    if (to.name === 'login') return { name: 'nodes' }
    return true
  } catch {
    if (to.name === 'login') return true
    return { name: 'login', query: { next: to.fullPath } }
  }
})
