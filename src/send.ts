// sendMessage (D26, Part C): the one call to send. The caller's agent
// brings plaintext; this service fetches the recipient's key from the
// messaging service named in `resource`, encrypts, and delivers the
// ciphertext there, as an intermediary acting on the caller's person
// token. Nothing here names a messaging service: `resource` is required.
//
//   1. body: resource (an https origin), to, text (≤ 64 KB), from?,
//      idempotency_key?. `attachments` is refused (D25: text only).
//   2. person token for `resource` over the chain (chain.ts).
//   3. GET {resource}/keys?address={to}; not_connected and
//      recipient_has_no_key pass through verbatim.
//   4. JWE ECDH-ES + A256GCM to the first key, split (jwe.ts).
//   5. POST {resource}/messages, then PUT {resource}/messages/{id}/blob as
//      application/octet-stream. Refusals pass through.
//   6. {id, to, from, kid, size, resource}.
import type { Context } from 'hono'
import { parseJsonBody } from './auth'
import { chainedFetch, passThrough } from './chain'
import { emit } from './events'
import { encryptTo, JweError, publicP256 } from './jwe'
import type { HonoEnv } from './types'
import { identityHash } from './util'

/** D25: plaintext {text} up to 64 KB; the ciphertext is the same length. */
export const MAX_CIPHERTEXT = 65_536
const MAX_ADDRESS = 320
const MAX_IDEMPOTENCY_KEY = 64

interface SendBody {
  resource?: unknown
  to?: unknown
  text?: unknown
  from?: unknown
  idempotency_key?: unknown
  attachments?: unknown
}

/** An https origin, exactly: no path, query, fragment, or trailing slash. */
export function parseResource(input: unknown): string | null {
  if (typeof input !== 'string' || input.length > 253 + 8) return null
  let u: URL
  try {
    u = new URL(input)
  } catch {
    return null
  }
  if (u.protocol !== 'https:' || u.username || u.password) return null
  if (u.origin !== input) return null
  return u.origin
}

export async function sendMessage(c: Context<HonoEnv>): Promise<Response> {
  const id = c.get('identity')
  const who = await identityHash(id.iss, id.sub)
  const body = parseJsonBody<SendBody>(c)
  if (!body) return c.json({ error: 'invalid_json' }, 400)

  // ── 1. the request ──
  if (body.attachments !== undefined) {
    emit(c, { event: 'send_refused', code: 'attachments_not_supported', identity: who })
    return c.json({ error: 'attachments_not_supported', detail: 'this service sends text only (D25); attachments come later' }, 400)
  }
  const resource = parseResource(body.resource)
  if (!resource) return c.json({ error: 'invalid_request', field: 'resource', detail: 'the messaging service to deliver to, as an https origin (see llms.txt for the default)' }, 400)
  const to = typeof body.to === 'string' ? body.to.trim() : ''
  if (!to || to.length > MAX_ADDRESS || /\s/.test(to)) return c.json({ error: 'invalid_request', field: 'to', detail: 'the recipient identifier URI, e.g. mailto:bob@example.com' }, 400)
  if (typeof body.text !== 'string') return c.json({ error: 'invalid_request', field: 'text', detail: 'the message text (string)' }, 400)
  const from = body.from === undefined ? undefined : typeof body.from === 'string' && body.from.trim() && body.from.length <= MAX_ADDRESS && !/\s/.test(body.from) ? body.from.trim() : null
  if (from === null) return c.json({ error: 'invalid_request', field: 'from', detail: 'one of your identifier URIs' }, 400)
  const idempotencyKey = body.idempotency_key === undefined ? undefined : typeof body.idempotency_key === 'string' && body.idempotency_key && body.idempotency_key.length <= MAX_IDEMPOTENCY_KEY ? body.idempotency_key : null
  if (idempotencyKey === null) return c.json({ error: 'invalid_request', field: 'idempotency_key', detail: `1..${MAX_IDEMPOTENCY_KEY} characters` }, 400)
  const plaintext = new TextEncoder().encode(JSON.stringify({ text: body.text }))
  if (plaintext.byteLength > MAX_CIPHERTEXT) {
    emit(c, { event: 'send_refused', code: 'text_too_long', identity: who, size: plaintext.byteLength })
    return c.json({ error: 'text_too_long', detail: `the text is ${plaintext.byteLength} bytes as JSON; the limit is ${MAX_CIPHERTEXT} (64 KB)` }, 413)
  }

  // ── 2. person token for the resource ──
  const chain = await chainedFetch(c.env, id.jwt, resource)
  if (!chain.ok) {
    emit(c, { event: 'chain_failed', level: 40, step: 'person_token', code: chain.error, detail: chain.detail, ps: id.iss, resource, identity: who })
    return c.json({ error: chain.error, detail: `no person token for ${resource} from ${id.iss}: ${chain.detail}`, step: 'person_token' }, 502)
  }
  emit(c, { event: 'chain_person_token', ok: true, ps: id.iss, resource, identity: who })
  const fetchAs = chain.fetch

  // ── 3. the recipient's key ──
  let res: Response
  try {
    res = await fetchAs(`${resource}/keys?address=${encodeURIComponent(to)}`, { method: 'GET', headers: { accept: 'application/json' } })
  } catch (err) {
    emit(c, { event: 'chain_failed', level: 40, step: 'get_keys', code: 'resource_unreachable', detail: String(err), resource, identity: who })
    return c.json({ error: 'resource_unreachable', detail: `${resource} did not answer: ${String(err)}`, step: 'get_keys' }, 502)
  }
  if (res.status !== 200) {
    const refusal = await passThrough(res)
    emit(c, { event: 'send_refused', code: refusal.error, step: 'get_keys', status: res.status, resource, identity: who })
    return c.json({ ...refusal, step: 'get_keys', resource }, res.status as 404)
  }
  const keysBody = (await res.json()) as { keys?: Array<{ kid?: unknown; alg?: unknown; jwk?: unknown }> }
  const key = Array.isArray(keysBody.keys) ? keysBody.keys.find((k) => k.alg === 'ECDH-ES' && typeof k.kid === 'string' && publicP256(k.jwk)) : undefined
  if (!key) {
    emit(c, { event: 'send_refused', code: 'recipient_has_no_key', step: 'get_keys', resource, identity: who })
    return c.json({ error: 'recipient_has_no_key', detail: `${resource} lists no ECDH-ES P-256 key for that address`, step: 'get_keys', resource }, 409)
  }
  const kid = key.kid as string

  // ── 4. encrypt ──
  let envelope
  try {
    envelope = await encryptTo(key.jwk as JsonWebKey, kid, plaintext)
  } catch (err) {
    if (err instanceof JweError) return c.json({ error: err.code, detail: err.message, step: 'encrypt' }, 502)
    throw err
  }
  const size = envelope.ciphertext.byteLength

  // ── 5. deliver ──
  const metadata: Record<string, unknown> = { to, protected: envelope.protected, iv: envelope.iv, tag: envelope.tag, size }
  if (from) metadata.from = from
  if (idempotencyKey) metadata.idempotency_key = idempotencyKey
  try {
    res = await fetchAs(`${resource}/messages`, { method: 'POST', headers: { 'content-type': 'application/json', accept: 'application/json' }, body: JSON.stringify(metadata) })
  } catch (err) {
    emit(c, { event: 'chain_failed', level: 40, step: 'send_message', code: 'resource_unreachable', detail: String(err), resource, identity: who })
    return c.json({ error: 'resource_unreachable', detail: `${resource} did not answer: ${String(err)}`, step: 'send_message' }, 502)
  }
  if (res.status !== 201 && res.status !== 200) {
    const refusal = await passThrough(res)
    emit(c, { event: 'send_refused', code: refusal.error, step: 'send_message', status: res.status, resource, identity: who })
    return c.json({ ...refusal, step: 'send_message', resource }, res.status as 409)
  }
  const created = (await res.json()) as { id?: unknown; from?: unknown; replayed?: unknown; blob_at?: unknown }
  if (typeof created.id !== 'string') return c.json({ error: 'invalid_response', detail: `${resource} answered sendMessage without an id`, step: 'send_message' }, 502)
  const messageId = created.id
  if (created.replayed && created.blob_at) {
    // An idempotent replay whose blob is already stored: nothing to upload.
    emit(c, { event: 'message_sent', replayed: true, message_id: messageId, kid, size, resource, identity: who })
    return c.json({ id: messageId, to, from: created.from ?? from, kid, size, resource, replayed: true })
  }
  try {
    res = await fetchAs(`${resource}/messages/${encodeURIComponent(messageId)}/blob`, {
      method: 'PUT',
      headers: { 'content-type': 'application/octet-stream', accept: 'application/json' },
      body: envelope.ciphertext as BodyInit,
    })
  } catch (err) {
    emit(c, { event: 'chain_failed', level: 40, step: 'put_blob', code: 'resource_unreachable', detail: String(err), message_id: messageId, resource, identity: who })
    return c.json({ error: 'resource_unreachable', detail: `${resource} did not answer the upload: ${String(err)}`, step: 'put_blob', id: messageId }, 502)
  }
  if (res.status !== 200) {
    const refusal = await passThrough(res)
    emit(c, { event: 'send_refused', code: refusal.error, step: 'put_blob', status: res.status, message_id: messageId, resource, identity: who })
    return c.json({ ...refusal, step: 'put_blob', id: messageId, resource }, res.status as 409)
  }

  // ── 6. done ──
  emit(c, { event: 'message_sent', message_id: messageId, kid, size, resource, identity: who })
  return c.json({ id: messageId, to, from: created.from ?? from, kid, size, resource })
}
