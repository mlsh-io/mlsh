<script setup lang="ts">
import { onMounted, onUnmounted, ref } from 'vue'
import { useRouter } from 'vue-router'
import Btn from '@/components/Btn.vue'
import { api } from '@/api/client'
import type { ClusterMode } from '@/api/types'

const router = useRouter()
const email = ref('')
const password = ref('')
const confirm = ref('')
const submitting = ref(false)
const error = ref<string | null>(null)
const mode = ref<ClusterMode | null>(null)

const device = ref<{ user_code: string; verification_uri: string; ticket: string } | null>(null)
const polling = ref(false)
let pollTimer: number | null = null

onMounted(async () => {
  try {
    mode.value = (await api.bootstrapStatus()).mode
  } catch {
    /* keep mode null — the form path will still work in self-hosted */
  }
})

onUnmounted(() => {
  if (pollTimer !== null) clearTimeout(pollTimer)
})

async function submit() {
  error.value = null
  if (!email.value.trim() || !password.value) {
    error.value = 'Email and password are required.'
    return
  }
  if (password.value !== confirm.value) {
    error.value = 'Passwords do not match.'
    return
  }
  submitting.value = true
  try {
    await api.bootstrapCreate(email.value.trim(), password.value)
    router.replace('/nodes')
  } catch (e) {
    error.value = e instanceof Error ? e.message : String(e)
  } finally {
    submitting.value = false
  }
}

async function loginWithCloud() {
  error.value = null
  try {
    const resp = await api.deviceStart()
    device.value = {
      user_code: resp.user_code,
      verification_uri: resp.verification_uri,
      ticket: resp.ticket,
    }
    polling.value = true
    schedulePoll(resp.interval * 1000)
  } catch (e) {
    error.value = e instanceof Error ? e.message : String(e)
  }
}

function schedulePoll(delayMs: number) {
  pollTimer = window.setTimeout(pollOnce, delayMs)
}

async function pollOnce() {
  if (!device.value) return
  try {
    const status = await api.devicePoll(device.value.ticket)
    if (status === 'authorized') {
      polling.value = false
      router.replace('/nodes')
      return
    }
    if (status === 'gone') {
      polling.value = false
      device.value = null
      error.value = 'Login window expired or failed. Try again.'
      return
    }
    // 'pending' — keep polling
    schedulePoll(2000)
  } catch (e) {
    polling.value = false
    error.value = e instanceof Error ? e.message : String(e)
  }
}

function cancelDevice() {
  if (pollTimer !== null) clearTimeout(pollTimer)
  device.value = null
  polling.value = false
}
</script>

<template>
  <div class="page">
    <div class="card">
      <h1>Welcome to mlsh-control</h1>
      <p v-if="mode === 'managed'" class="lede">
        Sign in with your mlsh.io account to take control of this cluster.
      </p>
      <p v-else class="lede">
        No admin user exists yet. Create the first one to take control of this cluster.
      </p>

      <div v-if="mode === 'managed'" class="form">
        <div v-if="device" class="device-card">
          <p>1. Open this URL on any device:</p>
          <p><a :href="device.verification_uri" target="_blank" rel="noopener">{{ device.verification_uri }}</a></p>
          <p>2. Enter this code:</p>
          <pre class="user-code">{{ device.user_code }}</pre>
          <p class="hint">Waiting for authorization{{ polling ? '…' : '' }}</p>
          <Btn variant="ghost" @click="cancelDevice">Cancel</Btn>
        </div>
        <Btn v-else variant="primary" @click="loginWithCloud">Login with mlsh.io</Btn>
        <p v-if="error" class="error">{{ error }}</p>
      </div>

      <form v-else @submit.prevent="submit" class="form">
        <label>
          <span>Email</span>
          <input v-model="email" type="email" autocomplete="username" required autofocus />
        </label>
        <label>
          <span>Password</span>
          <input v-model="password" type="password" autocomplete="new-password" required />
        </label>
        <label>
          <span>Confirm</span>
          <input v-model="confirm" type="password" autocomplete="new-password" required />
        </label>
        <p v-if="error" class="error">{{ error }}</p>
        <Btn variant="primary" type="submit" :disabled="submitting">
          {{ submitting ? 'Creating…' : 'Create admin' }}
        </Btn>
      </form>
    </div>
  </div>
</template>

<style scoped>
.page {
  min-height: 100vh;
  display: grid;
  place-items: center;
  padding: var(--space-8);
}
.card {
  width: 100%;
  max-width: 420px;
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: var(--radius);
  padding: var(--space-8);
}
h1 {
  margin: 0 0 var(--space-2);
  font-size: 22px;
  color: var(--gold);
}
.lede {
  color: var(--text-dim);
  margin: 0 0 var(--space-6);
  font-size: 14px;
}
.form {
  display: flex;
  flex-direction: column;
  gap: var(--space-4);
}
label {
  display: flex;
  flex-direction: column;
  gap: 6px;
  font-size: 13px;
}
label span {
  color: var(--text-dim);
}
input {
  background: var(--bg);
  border: 1px solid var(--border);
  border-radius: var(--radius);
  padding: 8px 10px;
  color: var(--text);
  font: inherit;
}
input:focus {
  outline: none;
  border-color: var(--gold);
}
.error {
  color: var(--red);
  font-size: 13px;
  margin: 0;
}
.device-card {
  display: flex;
  flex-direction: column;
  gap: var(--space-3);
}
.user-code {
  font-family: var(--font-mono);
  font-size: 22px;
  letter-spacing: 0.2em;
  background: var(--bg);
  border: 1px solid var(--gold);
  border-radius: var(--radius);
  padding: var(--space-3);
  text-align: center;
  color: var(--gold);
  margin: 0;
}
.hint {
  color: var(--text-dim);
  font-size: 13px;
}
a {
  color: var(--gold);
}
</style>