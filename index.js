import { readFileSync } from "node:fs"
import { accountId, createOAuth } from "./oauth.js"
import { codexFetch } from "./responses.js"

const ID = "openai-codex-legacy"
const BASE = "https://chatgpt.com/backend-api/codex"
const ICON = `data:image/svg+xml;base64,${readFileSync(new URL("./icon.svg", import.meta.url)).toString("base64")}`

export const OpenAICodexLegacyPlugin = async ({ client, magpie }) => {
  const oauth = createOAuth()
  return {
    config: async (cfg) => {
      cfg.provider ??= {}
      cfg.provider[ID] = {
        ...cfg.provider[ID],
        name: "OpenAI Codex (legacy OAuth)",
        npm: "@ai-sdk/openai",
        api: BASE,
        models: cfg.provider[ID]?.models ?? {},
      }
    },
    provider: {
      id: ID,
      async models(provider, { auth }) {
        if (auth?.type !== "oauth") return provider.models
        const response = await fetch(`${BASE}/models?client_version=0.161.1`, {
          headers: {
            authorization: `Bearer ${auth.access}`,
            "chatgpt-account-id": accountId(auth.access),
            originator: "codex_cli_rs",
          },
          signal: AbortSignal.timeout(30_000),
        })
        if (!response.ok) throw new Error(`Codex model list failed (HTTP ${response.status})`)
        const data = await response.json()
        if (!Array.isArray(data.models)) throw new Error("Invalid Codex model list")
        return Object.fromEntries(data.models.filter((m) => typeof m.slug === "string" && m.slug && m.visibility !== "hide").map((m) => [m.slug, {
          id: m.slug,
          providerID: ID,
          name: m.display_name || m.slug,
          api: { id: m.slug, url: BASE, npm: "@ai-sdk/openai" },
          limit: { context: m.context_window ?? 0, output: m.max_output_tokens ?? 0 },
          capabilities: {
            temperature: false, reasoning: true, attachment: true, toolcall: true,
            input: { text: true, image: true }, output: { text: true },
          },
          variants: Object.fromEntries((m.supported_reasoning_levels ?? []).filter((r) => typeof r.effort === "string").map((r) => [r.effort, { reasoningEffort: r.effort }])),
        }]))
      },
    },
    auth: {
      provider: ID,
      icon: ICON,
      methods: [
        { type: "oauth", label: "Browser login (paste callback URL)", authorize: () => oauth.browser() },
        { type: "oauth", label: "Device code login (headless)", authorize: () => oauth.device() },
      ],
      // Magpie serializes this per account and persists the rotated tokens.
      refresh: (auth) => oauth.refresh(auth),
      loader: async (getAuth) => {
        // OpenCode does not call Magpie's refresh hook. Its fallback is also
        // serialized per loader/account, never shared between different users.
        let renewing
        async function credentials() {
          let auth = await getAuth()
          if (auth?.type !== "oauth") throw new Error("Sign in to OpenAI Codex (legacy) first")
          if (auth.expires <= Date.now()) {
            // Do not compete with the host's refresh still running after its
            // bounded wait, or reuse a refresh token after a failed renewal.
            if (magpie) throw new Error("Codex token is expired and renewal has not completed; retry or sign in again")
            renewing ??= (async () => {
              const updated = { ...auth, ...await oauth.refresh(auth) }
              await client.auth.set({ path: { id: ID }, body: updated })
              return updated
            })().finally(() => { renewing = undefined })
            auth = await renewing
          }
          return auth
        }
        return { apiKey: "oauth", fetch: codexFetch(credentials) }
      },
    },
  }
}
