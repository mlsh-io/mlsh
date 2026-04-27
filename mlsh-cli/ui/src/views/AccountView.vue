<script setup lang="ts">
import { onMounted, ref, watch } from 'vue'
import QRCode from 'qrcode'
import Btn from '@/components/Btn.vue'
import { api } from '@/api/client'
import type { SessionUser, SessionView, TotpEnrollment, WebauthnCredential } from '@/api/types'

const me = ref<SessionUser | null>(null)
const sessions = ref<SessionView[]>([])
const passkeys = ref<WebauthnCredential[]>([])

const totpEnrollment = ref<TotpEnrollment | null>(null)
const totpCode = ref('')
const totpError = ref<string | null>(null)
const totpVerified = ref(false)
const totpQrDataUrl = ref<string | null>(null)

watch(totpEnrollment, async (enrollment) => {
  if (!enrollment) {
    totpQrDataUrl.value = null
    return
  }
  try {
    totpQrDataUrl.value = await QRCode.toDataURL(enrollment.otpauth_uri, {
      margin: 1,
      width: 220,
      color: { dark: '#000000', light: '#ffffff' },
    })
  } catch {
    totpQrDataUrl.value = null
  }
})

const error = ref<string | null>(null)

async function reload() {
  error.value = null
  try {
    me.value = await api.whoamiSession()
    sessions.value = await api.listSessions()
    passkeys.value = await api.webauthnCredentials().catch(() => [])
  } catch (e) {
    error.value = e instanceof Error ? e.message : String(e)
  }
}

async function startTotpEnroll() {
  totpError.value = null
  totpVerified.value = false
  totpCode.value = ''
  totpEnrollment.value = await api.totpEnroll()
}

async function verifyTotp() {
  if (!totpCode.value) return
  totpError.value = null
  try {
    await api.totpVerify(totpCode.value)
    totpVerified.value = true
    totpEnrollment.value = null
  } catch (e) {
    totpError.value = e instanceof Error ? e.message : String(e)
  }
}

async function deleteTotp() {
  if (!confirm('Remove TOTP from this account?')) return
  await api.totpDelete()
  totpVerified.value = false
}

async function revoke(id: string) {
  await api.revokeSession(id)
  await reload()
}

async function deletePasskey(id: string) {
  if (!confirm('Remove this passkey?')) return
  await api.webauthnDelete(id)
  passkeys.value = await api.webauthnCredentials()
}

onMounted(reload)
</script>

<template>
  <section class="page">
    <h1>Account</h1>
    <p v-if="error" class="error">{{ error }}</p>

    <div class="card">
      <h2>Profile</h2>
      <p v-if="me"><span class="label">Email</span> {{ me.email }}</p>
    </div>

    <div class="card">
      <h2>Two-factor authentication (TOTP)</h2>
      <p class="hint">
        Adds an extra step to sensitive actions. Use any RFC 6238 authenticator
        (1Password, Authy, Aegis, …).
      </p>

      <div v-if="totpEnrollment" class="enroll">
        <p>Scan this QR code with your authenticator app:</p>
        <img v-if="totpQrDataUrl" :src="totpQrDataUrl" alt="TOTP QR code" class="qr" />
        <details class="manual">
          <summary>Can't scan? Enter manually</summary>
          <p class="hint">Key (base32): <code>{{ totpEnrollment.secret_base32 }}</code></p>
          <pre class="uri">{{ totpEnrollment.otpauth_uri }}</pre>
        </details>
        <form @submit.prevent="verifyTotp" class="row">
          <input v-model="totpCode" placeholder="6-digit code" inputmode="numeric" pattern="[0-9]*" />
          <Btn variant="primary" type="submit">Confirm</Btn>
        </form>
        <p v-if="totpError" class="error">{{ totpError }}</p>
      </div>

      <div v-else>
        <p v-if="totpVerified" class="ok">TOTP enrolled.</p>
        <div class="row">
          <Btn variant="primary" @click="startTotpEnroll">Enroll / replace</Btn>
          <Btn variant="danger" @click="deleteTotp">Remove</Btn>
        </div>
      </div>
    </div>

    <div class="card">
      <h2>Passkeys (WebAuthn)</h2>
      <p class="hint">
        Registration is initiated from your device. If WebAuthn is not configured on
        this control plane, the buttons return 503.
      </p>
      <ul v-if="passkeys.length" class="list">
        <li v-for="p in passkeys" :key="p.id">
          <span>{{ p.name }}</span>
          <Btn variant="danger" @click="deletePasskey(p.id)">Remove</Btn>
        </li>
      </ul>
      <p v-else class="hint">No passkeys enrolled.</p>
    </div>

    <div class="card">
      <h2>Active sessions</h2>
      <ul class="list">
        <li v-for="s in sessions" :key="s.id">
          <span>
            <span :class="['badge', s.revoked ? 'off' : s.current ? 'cur' : 'ok']">
              {{ s.revoked ? 'revoked' : s.current ? 'this session' : 'active' }}
            </span>
            <span class="muted">created {{ s.created_at }}</span>
          </span>
          <Btn v-if="!s.revoked && !s.current" variant="danger" @click="revoke(s.id)">Revoke</Btn>
        </li>
      </ul>
    </div>
  </section>
</template>

<style scoped>
.page { display: flex; flex-direction: column; gap: var(--space-6); }
h1 { margin: 0; font-size: 22px; }
h2 { margin: 0 0 var(--space-3); font-size: 16px; color: var(--gold); }
.card {
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: var(--radius);
  padding: var(--space-6);
}
.hint { color: var(--text-dim); font-size: 13px; }
.label { color: var(--text-dim); margin-right: var(--space-2); }
.row { display: flex; gap: var(--space-3); align-items: center; margin-top: var(--space-3); }
.error { color: var(--red); }
.ok { color: var(--green); }
.uri {
  background: var(--bg);
  border: 1px solid var(--border);
  border-radius: var(--radius);
  padding: var(--space-3);
  font-size: 12px;
  overflow-x: auto;
  word-break: break-all;
  white-space: pre-wrap;
}
.qr {
  display: block;
  margin: var(--space-3) 0;
  border: 1px solid var(--border);
  border-radius: var(--radius);
  background: #fff;
  padding: 6px;
}
.manual {
  margin-top: var(--space-3);
  font-size: 13px;
}
.manual summary {
  cursor: pointer;
  color: var(--text-dim);
  user-select: none;
}
.manual summary:hover { color: var(--text); }
input {
  background: var(--bg);
  border: 1px solid var(--border);
  border-radius: var(--radius);
  padding: 8px 10px;
  color: var(--text);
  font: inherit;
  width: 140px;
}
.list { list-style: none; padding: 0; margin: var(--space-3) 0 0; display: flex; flex-direction: column; gap: var(--space-2); }
.list li {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: var(--space-2) 0;
  border-bottom: 1px solid var(--border);
  font-size: 13px;
}
.muted { color: var(--text-dim); margin-left: var(--space-2); font-family: var(--font-mono); font-size: 11px; }
.badge {
  font-size: 11px;
  padding: 2px 6px;
  border: 1px solid var(--border);
  border-radius: var(--radius);
  color: var(--text-dim);
  margin-right: var(--space-2);
}
.badge.ok { color: var(--green); border-color: rgba(74, 222, 128, 0.3); }
.badge.cur { color: var(--gold); border-color: var(--gold); }
.badge.off { color: var(--red); border-color: rgba(248, 113, 113, 0.3); }
</style>
