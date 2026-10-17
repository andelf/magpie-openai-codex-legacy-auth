import { createHash, randomBytes, timingSafeEqual } from "node:crypto"
import { setTimeout as sleep } from "node:timers/promises"

const CLIENT_ID = "app_EMoamEEZ73f0CkXaXp7hrann"
const AUTH = "https://auth.openai.com"
const REDIRECT = "http://localhost:1455/auth/callback"
const DEVICE_REDIRECT = `${AUTH}/deviceauth/callback`
const CLAIM = "https://api.openai.com/auth"
const LOGIN_TIMEOUT = 15 * 60_000

// Dependencies are injectable for offline tests, never supplied by login input.
export function createOAuth({ request = fetch, now = Date.now, wait = (ms, signal) => sleep(ms, undefined, { signal }) } = {}) {
  async function post(path, body, signal, json = false) {
    return request(`${AUTH}${path}`, {
      method: "POST",
      headers: { "content-type": json ? "application/json" : "application/x-www-form-urlencoded" },
      body: json ? JSON.stringify(body) : new URLSearchParams(body),
      signal,
    })
  }

  async function token(body, signal) {
    const response = await post("/oauth/token", { client_id: CLIENT_ID, ...body }, signal)
    if (!response.ok) {
      let code
      try { code = (await response.json()).error } catch {}
      const error = new Error(`Codex token request failed (HTTP ${response.status}); sign in again if authorization was revoked`)
      if (code === "invalid_grant") error.signIn = "expired"
      throw error
    }
    const data = await response.json()
    if (typeof data.access_token !== "string" || !data.access_token ||
        typeof data.refresh_token !== "string" || !data.refresh_token ||
        !Number.isFinite(data.expires_in) || data.expires_in <= 0) {
      throw new Error("Codex token response is missing valid token or expiry fields")
    }
    accountId(data.access_token)
    return { access: data.access_token, refresh: data.refresh_token, expires: now() + data.expires_in * 1000 }
  }

  async function exchange(code, verifier, redirect, signal) {
    return { type: "success", ...await token({
      grant_type: "authorization_code", code, code_verifier: verifier, redirect_uri: redirect,
    }, signal) }
  }

  return {
    async browser() {
      const verifier = randomBytes(32).toString("base64url")
      const state = randomBytes(32).toString("hex")
      const deadline = now() + LOGIN_TIMEOUT
      const url = new URL(`${AUTH}/oauth/authorize`)
      url.search = new URLSearchParams({
        response_type: "code", client_id: CLIENT_ID, redirect_uri: REDIRECT,
        scope: "openid profile email offline_access", state,
        code_challenge: createHash("sha256").update(verifier).digest("base64url"),
        code_challenge_method: "S256", id_token_add_organizations: "true",
        codex_cli_simplified_flow: "true", originator: "codex_cli_rs",
      }).toString()
      let used = false
      return {
        url: url.href,
        method: "code",
        instructions: "Complete browser login, then paste the FULL localhost callback URL (including code and state). A localhost connection error is expected: this plugin does not open port 1455.",
        async callback(input) {
          if (used || now() >= deadline) throw new Error("Login expired or already completed; start again")
          const redirect = new URL(String(input).trim())
          if (redirect.origin !== "http://localhost:1455" || redirect.pathname !== "/auth/callback") {
            throw new Error("Paste the full localhost:1455/auth/callback URL")
          }
          const given = Buffer.from(redirect.searchParams.get("state") ?? "")
          const expected = Buffer.from(state)
          if (given.length !== expected.length || !timingSafeEqual(given, expected)) throw new Error("OAuth state mismatch")
          if (redirect.searchParams.has("error")) throw new Error("Browser authorization was refused")
          const code = redirect.searchParams.get("code")
          if (!code) throw new Error("Missing authorization code")
          used = true
          return exchange(code, verifier, REDIRECT, AbortSignal.timeout(30_000))
        },
      }
    },

    async device() {
      const response = await post("/api/accounts/deviceauth/usercode", { client_id: CLIENT_ID }, AbortSignal.timeout(30_000), true)
      if (!response.ok) throw new Error(`Device code request failed (HTTP ${response.status}); try browser login`)
      const data = await response.json()
      const interval = Number(data.interval)
      if (typeof data.device_auth_id !== "string" || !data.device_auth_id ||
          typeof data.user_code !== "string" || !data.user_code ||
          !["string", "number"].includes(typeof data.interval) ||
          (typeof data.interval === "string" && !data.interval.trim()) || !Number.isFinite(interval) || interval < 0) throw new Error("Invalid device code response")
      const deadline = now() + LOGIN_TIMEOUT
      let used = false
      return {
        url: `${AUTH}/codex/device`,
        method: "auto",
        instructions: `Enter device code: ${data.user_code}. Enable device code authorization in ChatGPT settings if requested. This code expires in 15 minutes.`,
        async callback() {
          if (used) throw new Error("Device login already started; start again")
          used = true
          const remaining = deadline - now()
          if (remaining <= 0) throw new Error("Device login timed out; start again")
          const signal = AbortSignal.timeout(remaining)
          let delay = Math.max(1000, interval * 1000)
          while (now() < deadline) {
            signal.throwIfAborted()
            const result = await post("/api/accounts/deviceauth/token", {
              device_auth_id: data.device_auth_id, user_code: data.user_code,
            }, signal, true)
            if (result.ok) {
              const code = await result.json()
              if (typeof code.authorization_code !== "string" || !code.authorization_code ||
                  typeof code.code_verifier !== "string" || !code.code_verifier) throw new Error("Invalid device authorization response")
              return exchange(code.authorization_code, code.code_verifier, DEVICE_REDIRECT, signal)
            }
            let error
            try { const body = await result.json(); error = typeof body.error === "string" ? body.error : body.error?.code } catch {}
            if (error === "slow_down") delay += 5000
            else if (result.status !== 403 && result.status !== 404 && error !== "deviceauth_authorization_pending") {
              throw new Error(`Device authorization failed (HTTP ${result.status})`)
            }
            await wait(Math.min(delay, Math.max(0, deadline - now())), signal)
          }
          throw new Error("Device login timed out; start again")
        },
      }
    },

    refresh(auth) {
      return token({ grant_type: "refresh_token", refresh_token: auth.refresh }, AbortSignal.timeout(30_000))
    },
  }
}

// JWT claims identify the account; this is not signature verification.
export function accountId(access) {
  let id
  try { id = JSON.parse(Buffer.from(access.split(".")[1], "base64url").toString())[CLAIM]?.chatgpt_account_id } catch {}
  if (typeof id !== "string" || !id) throw new Error("Codex access token has no ChatGPT account ID")
  return id
}
