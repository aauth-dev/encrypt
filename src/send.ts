// sendMessage (D27, section 6a): the one call to send. The caller's agent
// brings plaintext; this service fetches the recipient's latest key from the
// messaging service, encrypts {text} as a compact JWE, and uploads it
// there, as an intermediary acting on the caller's person token. The
// messaging service is `resource`, default DEFAULT_RESOURCE (Q7); nothing
// here names one.
//
//   1. person token for `resource` over the chain (chain.ts).
//   2. getPublicKey {from, to}: GET {resource}/public-key?from=&to=.
//   3. encrypt {"text": …} as a compact JWE (jwe.ts, 8a).
//   4. uploadMessage {from, to, jwe}: POST {resource}/messages. On
//      409 key_rotated, back to step 2, once (5d, Q3).
//
// Refusals from the messaging service pass through with
// step: get_public_key | upload_message.
import type { Context } from 'hono'
import { parseJsonBody } from './auth'
import { chainedFetch, passThrough } from './chain'
import { emit } from './events'
import { encryptCompact, JweError, publicP256 } from './jwe'
import type { HonoEnv } from './types'
import { identityHash } from './util'

/** D25, 8b: {"text": …} up to 64 KB as UTF-8 JSON. */
export const MAX_PLAINTEXT = 65_536
const MAX_ADDRESS = 320
const MAX_IDEMPOTENCY_KEY = 64

interface SendBody {
  resource?: unknown
  from?: unknown
  to?: unknown
  text?: unknown
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

const address = (v: unknown): string | null => (typeof v === 'string' && v.trim() && v.length <= MAX_ADDRESS && !/\s/.test(v.trim()) ? v.trim() : null)

export async function sendMessage(c: Context<HonoEnv>): Promise<Response> {
  const id = c.get('identity')
  const who = await identityHash(id.iss, id.sub)
  const body = parseJsonBody<SendBody>(c)
  if (!body) return c.json({ error: 'invalid_json' }, 400)

  // ── the request ──
  if (body.attachments !== undefined) {
    emit(c, { event: 'send_refused', code: 'attachments_not_supported', identity: who })
    return c.json({ error: 'attachments_not_supported', detail: 'this service sends text only; attachments come later (Q8)' }, 400)
  }
  const resource = body.resource === undefined ? parseResource(c.env.DEFAULT_RESOURCE) : parseResource(body.resource)
  if (!resource) return c.json({ error: 'invalid_request', field: 'resource', detail: 'the messaging service to deliver to, as an https origin; leave it out for the default' }, 400)
  const from = address(body.from)
  if (!from) return c.json({ error: 'invalid_request', field: 'from', detail: 'required: the address you are sending from, one of yours at the messaging service, e.g. mailto:you@example.com' }, 400)
  const to = address(body.to)
  if (!to) return c.json({ error: 'invalid_request', field: 'to', detail: 'the recipient address, e.g. mailto:bob@example.com' }, 400)
  if (typeof body.text !== 'string') return c.json({ error: 'invalid_request', field: 'text', detail: 'the message text (string)' }, 400)
  const idempotencyKey = body.idempotency_key === undefined ? undefined : typeof body.idempotency_key === 'string' && body.idempotency_key && body.idempotency_key.length <= MAX_IDEMPOTENCY_KEY ? body.idempotency_key : null
  if (idempotencyKey === null) return c.json({ error: 'invalid_request', field: 'idempotency_key', detail: `1..${MAX_IDEMPOTENCY_KEY} characters` }, 400)
  const plaintext = new TextEncoder().encode(JSON.stringify({ text: body.text }))
  if (plaintext.byteLength > MAX_PLAINTEXT) {
    emit(c, { event: 'send_refused', code: 'text_too_long', identity: who, size: plaintext.byteLength })
    return c.json({ error: 'text_too_long', detail: `the text is ${plaintext.byteLength} bytes as JSON; the limit is ${MAX_PLAINTEXT} (64 KB)` }, 413)
  }

  // ── 1. person token for the resource ──
  const chain = await chainedFetch(c.env, id.jwt, resource)
  if (!chain.ok) {
    emit(c, { event: 'chain_failed', level: 40, step: 'person_token', code: chain.error, detail: chain.detail, ps: id.iss, resource, identity: who })
    return c.json({ error: chain.error, detail: `no person token for ${resource} from ${id.iss}: ${chain.detail}`, step: 'person_token', resource }, 502)
  }
  emit(c, { event: 'chain_person_token', ok: true, ps: id.iss, resource, identity: who })
  const fetchAs = chain.fetch

  const unreachable = (step: string, err: unknown) => {
    emit(c, { event: 'chain_failed', level: 40, step, code: 'resource_unreachable', detail: String(err), resource, identity: who })
    return c.json({ error: 'resource_unreachable', detail: `${resource} did not answer: ${String(err)}`, step, resource }, 502)
  }
  const refused = async (step: string, res: Response) => {
    const refusal = await passThrough(res)
    emit(c, { event: 'send_refused', code: refusal.error, step, status: res.status, resource, identity: who })
    // A 401 from the messaging service is about this service's chained token, not the caller's: do not challenge the caller.
    return c.json({ ...refusal, step, resource }, (res.status === 401 ? 502 : res.status) as 404)
  }

  // Steps 2 to 4, and once more from step 2 when the key rotated in between.
  for (let attempt = 0; ; attempt++) {
    // ── 2. getPublicKey ──
    let res: Response
    try {
      res = await fetchAs(`${resource}/public-key?from=${encodeURIComponent(from)}&to=${encodeURIComponent(to)}`, { method: 'GET', headers: { accept: 'application/json' } })
    } catch (err) {
      return unreachable('get_public_key', err)
    }
    if (res.status !== 200) return refused('get_public_key', res)
    const key = (await res.json().catch(() => null)) as { kid?: unknown; alg?: unknown; jwk?: unknown } | null
    if (!key || key.alg !== 'ECDH-ES' || typeof key.kid !== 'string' || !key.kid || !publicP256(key.jwk)) {
      emit(c, { event: 'send_refused', code: 'invalid_response', step: 'get_public_key', resource, identity: who })
      return c.json({ error: 'invalid_response', detail: `${resource} answered getPublicKey without {kid, alg: ECDH-ES, jwk: EC P-256}`, step: 'get_public_key', resource }, 502)
    }

    // ── 3. encrypt ──
    let jwe: string
    try {
      jwe = await encryptCompact(key.jwk as JsonWebKey, key.kid, plaintext)
    } catch (err) {
      if (err instanceof JweError) return c.json({ error: err.code, detail: err.message, step: 'encrypt', resource }, 502)
      throw err
    }

    // ── 4. uploadMessage ──
    const upload: Record<string, unknown> = { from, to, jwe }
    if (idempotencyKey) upload.idempotency_key = idempotencyKey
    try {
      res = await fetchAs(`${resource}/messages`, { method: 'POST', headers: { 'content-type': 'application/json', accept: 'application/json' }, body: JSON.stringify(upload) })
    } catch (err) {
      return unreachable('upload_message', err)
    }
    if (res.status === 409 && attempt === 0) {
      const refusal = await passThrough(res.clone())
      if (refusal.error === 'key_rotated') {
        emit(c, { event: 'key_rotated_retry', kid: key.kid, latest: refusal.kid, resource, identity: who })
        continue
      }
    }
    if (res.status !== 201 && res.status !== 200) return refused('upload_message', res)
    const stored = (await res.json().catch(() => null)) as { id?: unknown; from?: unknown; to?: unknown; kid?: unknown; size?: unknown; replayed?: unknown } | null
    if (!stored || typeof stored.id !== 'string') return c.json({ error: 'invalid_response', detail: `${resource} answered uploadMessage without an id`, step: 'upload_message', resource }, 502)

    emit(c, { event: 'message_sent', message_id: stored.id, kid: stored.kid ?? key.kid, size: stored.size ?? jwe.length, resource, identity: who, retried: attempt > 0, replayed: !!stored.replayed })
    // from and to as the messaging service shows them (its display forms).
    return c.json({
      id: stored.id, from: stored.from ?? from, to: stored.to ?? to, kid: stored.kid ?? key.kid, size: stored.size ?? jwe.length, resource,
      ...(stored.replayed ? { replayed: true } : {}),
    })
  }
}
