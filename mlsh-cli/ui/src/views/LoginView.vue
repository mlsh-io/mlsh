<script setup lang="ts">
import { nextTick, onMounted, onUnmounted, ref } from 'vue'
import { useRouter, useRoute } from 'vue-router'
import Btn from '@/components/Btn.vue'
import { api } from '@/api/client'
import type { ClusterMode } from '@/api/types'

const router = useRouter()
const route = useRoute()

const mode = ref<ClusterMode | null>(null)

// --- Self-hosted flow (email + password [+ TOTP]) ---
const email = ref('')
const password = ref('')
const totpCode = ref('')
const totpRequired = ref(false)
const submitting = ref(false)
const error = ref<string | null>(null)
const totpInput = ref<HTMLInputElement | null>(null)

// --- Managed flow (mlsh.io device code) ---
const device = ref<{ user_code: string; verification_uri: string; ticket: string } | null>(null)
const polling = ref(false)
let pollTimer: number | null = null

function verificationUrlWithCode(d: { user_code: string; verification_uri: string }): string {
  try {
    const u = new URL(d.verification_uri)
    u.searchParams.set('user_code', d.user_code)
    return u.toString()
  } catch {
    return d.verification_uri
  }
}

onMounted(async () => {
  try {
    mode.value = (await api.bootstrapStatus()).mode
  } catch {
    /* fall back to the password form on failure */
  }
})

onUnmounted(() => {
  if (pollTimer !== null) clearTimeout(pollTimer)
})

function nextPath(): string {
  const next = typeof route.query.next === 'string' ? route.query.next : '/nodes'
  return next.startsWith('/') ? next : '/nodes'
}

async function submit() {
  error.value = null
  if (!email.value.trim() || !password.value) {
    error.value = 'Email and password are required.'
    return
  }
  if (totpRequired.value && !totpCode.value.trim()) {
    error.value = 'Enter the 6-digit code from your authenticator.'
    return
  }
  submitting.value = true
  try {
    await api.login(
      email.value.trim(),
      password.value,
      totpRequired.value ? totpCode.value.trim() : undefined,
    )
    router.replace(nextPath())
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e)
    if (msg.includes('totp_required')) {
      totpRequired.value = true
      error.value = null
      nextTick(() => totpInput.value?.focus())
    } else if (msg.includes('totp_invalid')) {
      error.value = 'Invalid TOTP code. Try again.'
      totpCode.value = ''
      nextTick(() => totpInput.value?.focus())
    } else if (msg.includes('invalid_credentials') || msg.includes('401')) {
      error.value = 'Invalid email or password.'
      totpRequired.value = false
      totpCode.value = ''
    } else {
      error.value = msg
    }
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
      router.replace(nextPath())
      return
    }
    if (status === 'gone') {
      polling.value = false
      device.value = null
      error.value = 'Login window expired or failed. Try again.'
      return
    }
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
      <h1>Sign in</h1>
      <p class="lede">
        mlsh-control · {{ mode === 'managed' ? 'managed' : 'self-hosted' }}
      </p>

      <!-- Managed mode: device flow against mlsh.io -->
      <div v-if="mode === 'managed'" class="form">
        <div v-if="device" class="device-card">
          <p>Confirm this code on mlsh.io:</p>
          <pre class="user-code">{{ device.user_code }}</pre>
          <a
            class="cta"
            :href="verificationUrlWithCode(device)"
            target="_blank"
            rel="noopener"
          >
            Continue on mlsh.io →
          </a>
          <p class="hint">
            Or open <a :href="device.verification_uri" target="_blank" rel="noopener">{{ device.verification_uri }}</a> and enter the code manually.
          </p>
          <p class="hint">Waiting for authorization{{ polling ? '…' : '' }}</p>
          <Btn variant="ghost" @click="cancelDevice">Cancel</Btn>
        </div>
        <Btn v-else variant="primary" @click="loginWithCloud">Login with mlsh.io</Btn>
        <p v-if="error" class="error">{{ error }}</p>
      </div>

      <!-- Self-hosted mode: email + password [+ TOTP step-up] -->
      <form v-else @submit.prevent="submit" class="form">
        <label>
          <span>Email</span>
          <input
            v-model="email"
            type="email"
            autocomplete="username"
            required
            :disabled="totpRequired"
            autofocus
          />
        </label>
        <label>
          <span>Password</span>
          <input
            v-model="password"
            type="password"
            autocomplete="current-password"
            required
            :disabled="totpRequired"
          />
        </label>
        <label v-if="totpRequired">
          <span>6-digit code</span>
          <input
            ref="totpInput"
            v-model="totpCode"
            type="text"
            inputmode="numeric"
            pattern="[0-9]*"
            autocomplete="one-time-code"
            maxlength="6"
            required
          />
        </label>
        <p v-if="error" class="error">{{ error }}</p>
        <Btn variant="primary" type="submit" :disabled="submitting">
          {{ submitting ? 'Signing in…' : totpRequired ? 'Verify' : 'Sign in' }}
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
.error { color: var(--red); font-size: 13px; margin: 0; }

.device-card {
  display: flex;
  flex-direction: column;
  gap: var(--space-3);
}
.user-code {
  font-family: var(--font-mono);
  font-size: clamp(1rem, 5vw, 1.375rem);
  letter-spacing: 0.15em;
  word-break: break-all;
  white-space: pre-wrap;
  background: var(--bg);
  border: 1px solid var(--gold);
  border-radius: var(--radius);
  padding: var(--space-3);
  text-align: center;
  color: var(--gold);
  margin: 0;
}
.hint { color: var(--text-dim); font-size: 13px; }
a { color: var(--gold); }
.cta {
  display: inline-block;
  text-align: center;
  background: var(--gold);
  color: var(--bg);
  padding: 10px 14px;
  border-radius: var(--radius);
  font-weight: 600;
  text-decoration: none;
  margin-top: var(--space-2);
}
.cta:hover { filter: brightness(1.05); }
</style>
