import assert from "node:assert/strict"
import { createHash } from "node:crypto"
import { test } from "node:test"
import { accountId, createOAuth } from "../oauth.js"
import { codexFetch } from "../responses.js"
import { OpenAICodexLegacyPlugin } from "../index.js"

const access = (id = "account-1") => `header.${Buffer.from(JSON.stringify({ "https://api.openai.com/auth": { chatgpt_account_id: id } })).toString("base64url")}.signature`
const tokens = () => ({ access_token: access(), refresh_token: "rotated", expires_in: 3600 })
const auth = { type: "oauth", access: access(), refresh: "refresh", expires: Date.now() + 3600_000 }
const json = (body, status = 200) => Response.json(body, { status })
const noNetwork = async () => { throw new Error("Unexpected network request") }

// All outbound requests must be explicitly stubbed, including plugin hooks.
globalThis.fetch = noNetwork

test("browser uses legacy client, PKCE and validated one-shot callback state", async () => {
  let form
  const oauth = createOAuth({ request: async (url, init) => {
    assert.equal(url, "https://auth.openai.com/oauth/token")
    form = init.body
    return json(tokens())
  } })
  const flow = await oauth.browser()
  const url = new URL(flow.url)
  assert.equal(url.searchParams.get("client_id"), "app_EMoamEEZ73f0CkXaXp7hrann")
  assert.equal(url.searchParams.get("redirect_uri"), "http://localhost:1455/auth/callback")
  assert.equal(url.searchParams.get("code_challenge_method"), "S256")
  await assert.rejects(flow.callback("http://localhost:1455/auth/callback?code=c&state=wrong"), /state mismatch/)
  await assert.rejects(flow.callback("http://evil.example/auth/callback?code=c"), /full localhost/)
  await assert.rejects(flow.callback("bare-code"), { code: "ERR_INVALID_URL" })
  const result = await flow.callback(`http://localhost:1455/auth/callback?code=code&state=${url.searchParams.get("state")}`)
  assert.equal(result.type, "success")
  assert.equal(result.refresh, "rotated")
  assert.equal(form.get("code"), "code")
  assert.equal(createHash("sha256").update(form.get("code_verifier")).digest("base64url"), url.searchParams.get("code_challenge"))
  await assert.rejects(flow.callback("unused"), /already completed/)
})

test("browser expiration does not exchange credentials", async () => {
  let time = 0
  const flow = await createOAuth({ request: noNetwork, now: () => time }).browser()
  time = 15 * 60_000
  await assert.rejects(flow.callback("unused"), /expired/)
})

test("device pending, slow_down and code exchange use the device redirect", async () => {
  const waits = []
  const polls = [json({}, 403), json({ error: "slow_down" }, 400), json({ error: { code: "deviceauth_authorization_pending" } }, 400), json({ authorization_code: "device-code", code_verifier: "verifier" })]
  const oauth = createOAuth({ wait: async (ms) => { waits.push(ms) }, request: async (url, init) => {
    if (url.endsWith("/usercode")) {
      assert.deepEqual(JSON.parse(init.body), { client_id: "app_EMoamEEZ73f0CkXaXp7hrann" })
      return json({ device_auth_id: "device", user_code: "ABCD-EFGH", interval: "2" })
    }
    if (url.endsWith("/deviceauth/token")) {
      assert.deepEqual(JSON.parse(init.body), { device_auth_id: "device", user_code: "ABCD-EFGH" })
      return polls.shift()
    }
    assert.equal(url, "https://auth.openai.com/oauth/token")
    assert.equal(init.body.get("redirect_uri"), "https://auth.openai.com/deviceauth/callback")
    assert.equal(init.body.get("code_verifier"), "verifier")
    return json(tokens())
  } })
  const flow = await oauth.device()
  assert.equal(flow.method, "auto")
  assert.match(flow.instructions, /ABCD-EFGH/)
  assert.equal((await flow.callback()).access, access())
  assert.deepEqual(waits, [2000, 7000, 7000])
  await assert.rejects(flow.callback(), /already started/)
})

test("device deadline bounds polling even when the vendor keeps returning pending", async () => {
  let time = 0
  let polls = 0
  const oauth = createOAuth({ now: () => time, wait: async (ms) => { time += ms }, request: async (url) => {
    if (url.endsWith("/usercode")) return json({ device_auth_id: "d", user_code: "u", interval: 900 })
    polls++
    return json({}, 404)
  } })
  await assert.rejects((await oauth.device()).callback(), /timed out/)
  assert.equal(polls, 1)
})

test("malformed device response and permanent failure are not retried", async () => {
  for (const interval of [undefined, null, "", "oops", -1]) {
    await assert.rejects(createOAuth({ request: async () => json({ device_auth_id: "d", user_code: "u", interval }) }).device(), /Invalid device/)
  }
  const oauth = createOAuth({ request: async (url) => url.endsWith("/usercode")
    ? json({ device_auth_id: "d", user_code: "u", interval: 1 })
    : json({ error: "access_denied" }, 400) })
  await assert.rejects((await oauth.device()).callback(), /HTTP 400/)
})

test("refresh rotates tokens and marks only invalid_grant as expired", async () => {
  const oauth = createOAuth({ request: async (_url, init) => {
    assert.equal(init.body.get("grant_type"), "refresh_token")
    assert.equal(init.body.get("refresh_token"), "refresh")
    return json(tokens())
  } })
  assert.equal((await oauth.refresh(auth)).refresh, "rotated")
  for (const [code, status, expired] of [["invalid_grant", 400, true], ["server_error", 500, false]]) {
    const bad = createOAuth({ request: async () => json({ error: code, secret: "MUST-NOT-LEAK" }, status) })
    await assert.rejects(bad.refresh(auth), (error) => {
      assert.equal(error.signIn === "expired", expired)
      assert.doesNotMatch(error.message, /MUST-NOT-LEAK/)
      return true
    })
  }
  await assert.rejects(createOAuth({ request: async () => json({ ...tokens(), expires_in: "3600" }) }).refresh(auth), /missing valid/)
  assert.throws(() => accountId("invalid"), /account ID/)
})

test("Responses adapter isolates account headers, preserves tools and cancellation, and pins upstream", async () => {
  const controller = new AbortController()
  const tools = [{ type: "function", name: "test", parameters: { type: "object" } }]
  const run = codexFetch(async () => ({ ...auth, access: access("other-account") }), async (url, init) => {
    assert.equal(url, "https://chatgpt.com/backend-api/codex/responses")
    assert.equal(init.signal, controller.signal)
    assert.equal(init.headers.get("chatgpt-account-id"), "other-account")
    assert.equal(init.headers.get("authorization"), `Bearer ${access("other-account")}`)
    assert.equal(init.headers.has("x-api-key"), false)
    const body = JSON.parse(init.body)
    assert.equal(body.store, false)
    assert.equal(body.stream, true)
    assert.equal(body.max_output_tokens, undefined)
    assert.deepEqual(body.tools, tools)
    assert.deepEqual(body.reasoning, { effort: "high" })
    return new Response("data: test\n\n", { headers: { "content-type": "text/event-stream" } })
  })
  const response = await run("https://caller.invalid/responses", {
    method: "POST", signal: controller.signal, headers: { authorization: "wrong", "x-api-key": "wrong" },
    body: JSON.stringify({ stream: true, store: true, max_output_tokens: 123, tools, reasoning: { effort: "high" } }),
  })
  assert.equal(await response.text(), "data: test\n\n")
  await assert.rejects(run("https://caller.invalid/chat/completions", {}), /Responses|responses/)
})

test("non-streaming clients receive completed Responses JSON across split CRLF SSE frames", async () => {
  const result = { id: "resp_1", output: [{ type: "message", content: [{ type: "output_text", text: "你好" }] }], usage: { input_tokens: 12 } }
  const bytes = new TextEncoder().encode(`event: response.completed\r\ndata: ${JSON.stringify({ type: "response.completed", response: result })}\r\n\r\n`)
  const run = codexFetch(async () => auth, async () => new Response(new ReadableStream({
    start(controller) { for (let i = 0; i < bytes.length; i += 3) controller.enqueue(bytes.slice(i, i + 3)); controller.close() },
  })))
  const response = await run("https://local/responses", { body: JSON.stringify({ stream: false }) })
  assert.deepEqual(await response.json(), result)
})

test("truncated SSE fails instead of claiming an empty success; upstream HTTP errors pass through", async () => {
  const run = codexFetch(async () => auth, async () => new Response("data: {\"type\":\"response.created\"}\n\n"))
  await assert.rejects(run("https://local/responses", { body: "{}" }), /without a terminal/)
  const denied = codexFetch(async () => auth, async () => json({ error: { message: "quota" } }, 429))
  assert.equal((await denied("https://local/responses", { body: "{}" })).status, 429)
})

test("host-managed refresh never competes with an expired loader token", async () => {
  const plugin = await OpenAICodexLegacyPlugin({ client: {}, magpie: {} })
  const loader = await plugin.auth.loader(async () => ({ ...auth, expires: 1 }))
  await assert.rejects(loader.fetch("https://local/responses", { body: "{}" }), /renewal has not completed/)
})

test("OpenCode fallback refresh is serialized for concurrent requests", async (t) => {
  let current = { ...auth, expires: 1 }
  let refreshes = 0
  let saves = 0
  const previous = globalThis.fetch
  t.after(() => { globalThis.fetch = previous })
  globalThis.fetch = async (url) => {
    if (url.endsWith("/oauth/token")) {
      refreshes++
      await new Promise((resolve) => setImmediate(resolve))
      return json(tokens())
    }
    return new Response("data: [DONE]\\n\\n")
  }
  const plugin = await OpenAICodexLegacyPlugin({ client: { auth: { set: async ({ path, body }) => {
    assert.equal(path.id, "openai-codex-legacy")
    current = body
    saves++
  } } } })
  const loader = await plugin.auth.loader(async () => current)
  await Promise.all([1, 2].map(() => loader.fetch("https://local/responses", { body: JSON.stringify({ stream: true }) })))
  assert.equal(refreshes, 1)
  assert.equal(saves, 1)
  assert.equal(current.refresh, "rotated")
})

test("plugin exposes two login methods without taking over built-in Codex; models use the signed-in account", async (t) => {
  const plugin = await OpenAICodexLegacyPlugin({ client: {} })
  const cfg = { provider: { codex: { name: "untouched" } } }
  await plugin.config(cfg)
  assert.equal(cfg.provider.codex.name, "untouched")
  assert.equal(plugin.auth.provider, "openai-codex-legacy")
  assert.match(plugin.auth.icon, /^data:image\/svg\+xml;base64,/)
  assert.match(Buffer.from(plugin.auth.icon.split(",")[1], "base64").toString(), /<title>OpenAI<\/title>/)
  assert.equal(plugin.auth.methods.length, 2)
  assert.equal(cfg.provider[plugin.auth.provider].npm, "@ai-sdk/openai")
  const previous = globalThis.fetch
  t.after(() => { globalThis.fetch = previous })
  globalThis.fetch = async (url, init) => {
    assert.match(url, /\/codex\/models\?client_version=/)
    assert.equal(init.headers["chatgpt-account-id"], "account-1")
    return json({ models: [
      { slug: "model-1", display_name: "One", visibility: "list", context_window: 1000, supported_reasoning_levels: [{ effort: "low" }] },
      { slug: "hidden", visibility: "hide" },
    ] })
  }
  const models = await plugin.provider.models({ models: {} }, { auth })
  assert.deepEqual(Object.keys(models), ["model-1"])
  assert.equal(models["model-1"].api.npm, "@ai-sdk/openai")
  assert.deepEqual(models["model-1"].variants, { low: { reasoningEffort: "low" } })
})
