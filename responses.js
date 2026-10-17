import { accountId } from "./oauth.js"

const ENDPOINT = "https://chatgpt.com/backend-api/codex/responses"

export function codexFetch(credentials, request = fetch) {
  return async (url, init = {}) => {
    // Only implement Responses, and never send account credentials to an
    // address supplied by a caller or a model listing.
    if (!new URL(url).pathname.endsWith("/responses") || (init.method ?? "POST").toUpperCase() !== "POST") {
      throw new Error("Legacy Codex supports POST /responses only")
    }
    const body = JSON.parse(init.body)
    const streaming = body.stream === true
    body.store = false
    body.stream = true
    body.instructions ||= "You are a helpful assistant."
    // The subscription endpoint does not accept these public API parameters.
    for (const key of ["max_output_tokens", "max_completion_tokens", "temperature", "top_p"]) delete body[key]
    const auth = await credentials()
    const headers = new Headers(init.headers)
    headers.delete("x-api-key")
    headers.set("authorization", `Bearer ${auth.access}`)
    headers.set("chatgpt-account-id", accountId(auth.access))
    headers.set("originator", "codex_cli_rs")
    headers.set("OpenAI-Beta", "responses=experimental")
    headers.set("content-type", "application/json")
    headers.set("accept", "text/event-stream")
    const response = await request(ENDPOINT, { ...init, method: "POST", headers, body: JSON.stringify(body) })
    if (!response.ok || streaming) return response
    return completedResponse(response)
  }
}

// Codex always streams. Non-streaming gateway clients still need a normal
// Responses JSON object, not SSE bytes mislabeled as JSON.
async function completedResponse(response) {
  if (!response.body) throw new Error("Codex returned no response body")
  const reader = response.body.pipeThrough(new TextDecoderStream()).getReader()
  let buffer = ""
  try {
    while (true) {
      const { value, done } = await reader.read()
      if (done) throw new Error("Codex stream ended without a terminal response")
      buffer += value
      let match
      while ((match = /\r?\n\r?\n/.exec(buffer))) {
        const frame = buffer.slice(0, match.index)
        buffer = buffer.slice(match.index + match[0].length)
        const data = frame.split(/\r?\n/).filter((line) => line.startsWith("data:")).map((line) => line.slice(5).trimStart()).join("\n")
        if (!data || data === "[DONE]") continue
        const event = JSON.parse(data)
        if (["response.completed", "response.incomplete"].includes(event.type) && event.response) return Response.json(event.response)
        if (event.type === "response.failed" || event.type === "error") {
          return Response.json({ error: event.response?.error ?? event.error ?? { message: "Codex response failed" } }, { status: 502 })
        }
      }
    }
  } finally {
    await reader.cancel().catch(() => {})
    reader.releaseLock()
  }
}
