import assert from "node:assert/strict"
import { spawn, spawnSync } from "node:child_process"
import { existsSync } from "node:fs"
import { mkdtemp, rm, writeFile } from "node:fs/promises"
import { tmpdir } from "node:os"
import path from "node:path"
import { createInterface } from "node:readline"
import { fileURLToPath } from "node:url"
import { test } from "node:test"

const root = fileURLToPath(new URL("../", import.meta.url))
const bun = process.env.BUN_BIN || "bun"
const host = process.env.MAGPIE_REPO
  ? path.resolve(process.env.MAGPIE_REPO, "internal/plugin/host.js")
  : path.resolve(root, "../magpie/internal/plugin/host.js")
const available = existsSync(host) && spawnSync(bun, ["--version"], { stdio: "ignore" }).status === 0

test("real Magpie host loads the local package and exposes legacy OAuth login without vendor access", { skip: !available, timeout: 30_000 }, async (t) => {
  const home = await mkdtemp(path.join(tmpdir(), "codex-legacy-host-"))
  t.after(() => rm(home, { recursive: true, force: true }))
  const catalog = path.join(home, "models.json")
  await writeFile(catalog, "{}")
  const child = spawn(bun, ["--preload", path.join(root, "test/offline-preload.js"), host], {
    cwd: home,
    env: { ...process.env, HOME: home, USERPROFILE: home, XDG_CONFIG_HOME: home },
    stdio: ["pipe", "pipe", "pipe"],
  })
  const exited = new Promise((resolve) => child.once("exit", resolve))
  t.after(async () => { child.kill(); await exited })
  const waiting = new Map()
  let sequence = 0
  let stderr = ""
  child.stderr.on("data", (data) => { stderr += data })
  child.on("error", (error) => { for (const promise of waiting.values()) promise.reject(error) })
  child.on("exit", () => { for (const promise of waiting.values()) promise.reject(new Error(`Host exited: ${stderr}`)) })
  const lines = createInterface({ input: child.stdout })
  t.after(() => lines.close())
  lines.on("line", (line) => {
    const message = JSON.parse(line)
    const pending = waiting.get(message.id)
    if (!pending || message.event) return
    waiting.delete(message.id)
    if (message.error) pending.reject(new Error(JSON.stringify(message.error)))
    else pending.resolve(message.result)
  })
  const rpc = (method, params) => new Promise((resolve, reject) => {
    const id = ++sequence
    waiting.set(id, { resolve, reject })
    child.stdin.write(JSON.stringify({ id, method, params }) + "\n")
  })
  const loaded = await rpc("init", {
    authPath: path.join(home, "plugin-auth.json"), modelsDevPath: catalog, directory: home,
    plugins: [{ spec: root, target: root }],
  })
  assert.equal(loaded.plugins[0].error, undefined)
  assert.deepEqual(loaded.plugins[0].provides, ["openai-codex-legacy"])
  const providers = await rpc("providers", {})
  assert.match(providers[0].icon, /^data:image\/svg\+xml;base64,/)
  assert.match(Buffer.from(providers[0].icon.split(",")[1], "base64").toString(), /<title>OpenAI<\/title>/)
  const flow = await rpc("authorize", { provider: "openai-codex-legacy", method: 0 })
  assert.equal(flow.method, "code")
  assert.equal(new URL(flow.url).origin, "https://auth.openai.com")
  await assert.rejects(rpc("callback", {
    session: flow.session, code: "http://localhost:1455/auth/callback?state=bad&code=unused",
  }), /state mismatch/)
})
