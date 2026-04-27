<script setup lang="ts">
import { nextTick, ref } from 'vue'
import { useRouter, useRoute } from 'vue-router'
import Btn from '@/components/Btn.vue'
import { api } from '@/api/client'

const router = useRouter()
const route = useRoute()

const email = ref('')
const password = ref('')
const totpCode = ref('')
const totpRequired = ref(false)
const submitting = ref(false)
const error = ref<string | null>(null)
const totpInput = ref<HTMLInputElement | null>(null)

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
    const next = typeof route.query.next === 'string' ? route.query.next : '/nodes'
    router.replace(next.startsWith('/') ? next : '/nodes')
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
</script>

<template>
  <div class="page">
    <div class="card">
      <h1>Sign in</h1>
      <p class="lede">mlsh-control · self-hosted</p>

      <form @submit.prevent="submit" class="form">
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
</style>
