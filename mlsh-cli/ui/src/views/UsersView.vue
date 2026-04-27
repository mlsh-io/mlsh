<script setup lang="ts">
import { onMounted, ref } from 'vue'
import Btn from '@/components/Btn.vue'
import { api } from '@/api/client'
import type { ManagedUser } from '@/api/types'

const users = ref<ManagedUser[]>([])
const loading = ref(false)
const error = ref<string | null>(null)
const showCreate = ref(false)
const newEmail = ref('')
const newPassword = ref('')
const submitting = ref(false)
const mfaCode = ref('')

async function reload() {
  loading.value = true
  error.value = null
  try {
    users.value = await api.listUsers()
  } catch (e) {
    error.value = e instanceof Error ? e.message : String(e)
  } finally {
    loading.value = false
  }
}

async function createUser() {
  if (!newEmail.value.trim() || !newPassword.value) return
  submitting.value = true
  error.value = null
  try {
    await api.createUser(newEmail.value.trim(), newPassword.value)
    newEmail.value = ''
    newPassword.value = ''
    showCreate.value = false
    await reload()
  } catch (e) {
    error.value = e instanceof Error ? e.message : String(e)
  } finally {
    submitting.value = false
  }
}

async function toggleActive(u: ManagedUser) {
  error.value = null
  try {
    await api.updateUser(u.id, { active: !u.active }, mfaCode.value || undefined)
    await reload()
  } catch (e) {
    error.value = e instanceof Error ? e.message : String(e)
  }
}

async function deleteUser(u: ManagedUser) {
  if (!confirm(`Delete ${u.email}?`)) return
  error.value = null
  try {
    await api.deleteUser(u.id, mfaCode.value || undefined)
    await reload()
  } catch (e) {
    error.value = e instanceof Error ? e.message : String(e)
  }
}

onMounted(reload)
</script>

<template>
  <section>
    <header class="head">
      <h1>Users</h1>
      <Btn variant="primary" @click="showCreate = !showCreate">+ Add user</Btn>
    </header>

    <p class="hint">
      Sensitive actions may require a current TOTP code if you have one enrolled.
      <input v-model="mfaCode" placeholder="MFA code" class="mfa" />
    </p>

    <div v-if="showCreate" class="create-card">
      <h2>New user</h2>
      <form @submit.prevent="createUser" class="form">
        <label><span>Email</span><input v-model="newEmail" type="email" required /></label>
        <label><span>Password</span><input v-model="newPassword" type="password" required /></label>
        <div class="row">
          <Btn variant="primary" type="submit" :disabled="submitting">
            {{ submitting ? 'Creating…' : 'Create' }}
          </Btn>
          <Btn variant="ghost" type="button" @click="showCreate = false">Cancel</Btn>
        </div>
      </form>
    </div>

    <p v-if="error" class="error">{{ error }}</p>
    <p v-if="loading">Loading…</p>

    <table v-else class="users">
      <thead>
        <tr>
          <th>Email</th>
          <th>Source</th>
          <th>Status</th>
          <th></th>
        </tr>
      </thead>
      <tbody>
        <tr v-for="u in users" :key="u.id">
          <td>{{ u.email }}</td>
          <td><span class="badge">{{ u.source }}</span></td>
          <td>
            <span :class="['badge', u.active ? 'ok' : 'off']">
              {{ u.active ? 'active' : 'suspended' }}
            </span>
          </td>
          <td class="actions">
            <Btn @click="toggleActive(u)">{{ u.active ? 'Suspend' : 'Reactivate' }}</Btn>
            <Btn variant="danger" @click="deleteUser(u)">Delete</Btn>
          </td>
        </tr>
      </tbody>
    </table>
  </section>
</template>

<style scoped>
.head {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: var(--space-6);
}
h1 { margin: 0; font-size: 22px; }
.hint {
  color: var(--text-dim);
  font-size: 13px;
  display: flex;
  align-items: center;
  gap: var(--space-3);
}
.mfa {
  background: var(--bg);
  border: 1px solid var(--border);
  border-radius: var(--radius);
  padding: 4px 8px;
  color: var(--text);
  font: inherit;
  width: 100px;
}
.create-card {
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: var(--radius);
  padding: var(--space-6);
  margin: var(--space-6) 0;
}
.form { display: flex; flex-direction: column; gap: var(--space-4); }
label { display: flex; flex-direction: column; gap: 6px; font-size: 13px; }
label span { color: var(--text-dim); }
input {
  background: var(--bg);
  border: 1px solid var(--border);
  border-radius: var(--radius);
  padding: 8px 10px;
  color: var(--text);
  font: inherit;
}
input:focus { outline: none; border-color: var(--gold); }
.row { display: flex; gap: var(--space-3); }
.error { color: var(--red); margin: var(--space-3) 0; }

table.users {
  width: 100%;
  border-collapse: collapse;
  font-size: 13px;
  margin-top: var(--space-4);
}
table.users th, table.users td {
  text-align: left;
  padding: var(--space-3) var(--space-4);
  border-bottom: 1px solid var(--border);
}
table.users th { color: var(--text-dim); font-weight: 500; }
.badge {
  font-size: 11px;
  padding: 2px 6px;
  border: 1px solid var(--border);
  border-radius: var(--radius);
  color: var(--text-dim);
}
.badge.ok { color: var(--green); border-color: rgba(74, 222, 128, 0.3); }
.badge.off { color: var(--red); border-color: rgba(248, 113, 113, 0.3); }
.actions { display: flex; gap: var(--space-2); justify-content: flex-end; }
</style>
