// sendMessage (plan read-send-services section 6a) end to end against the
// fake PS (with the HTTP person_token_endpoint for the chain) and a fake
// messaging service at a non-agent.coop host: `resource` is a parameter and
// its default comes from DEFAULT_RESOURCE. Every status code of 6a, the
// key_rotated retry (5d, once), and what the messaging service sees of the
// chain (section 10). The compact JWE that arrives is decrypted with jose
// using the recipient's private key; the encoder is also checked against
// the interop vectors' keys.
import { beforeAll, describe, expect, it } from 'vitest'
import { SELF, env } from 'cloudflare:test'
import { clearMetadataCache } from '@aauth/resource'
import { compactDecrypt, decodeProtectedHeader, importJWK, jwtVerify } from 'jose'
import { Agent, FakePS, FakeSecret, RESOURCE, SECRET } from './fake-ps'
import { agentSub, agentToken, resetAgentTokenCache } from '../src/agent-identity'
import { encryptCompact, publicP256 } from '../src/jwe'
import { MAX_PLAINTEXT, parseResource } from '../src/send'
import joseVector from '../spec/vectors/jose.json'
import jwcryptoVector from '../spec/vectors/jwcrypto.json'

let ps: FakePS
let secret: FakeSecret
let alice: Agent

const ALICE = { handle: 'alice', email: 'alice@example.com' }
const FROM = 'mailto:alice@example.com'
const BOB = 'mailto:bob@example.com'

interface Sent { id: string; from: string; to: string; kid: string; size: number; resource: string; replayed?: boolean }
interface Refusal { error: string; detail?: string; step?: string; resource?: string }

/** Decrypt a compact JWE with jose. */
async function decryptWithJose(privateJwk: JsonWebKey, jwe: string): Promise<string> {
  const { plaintext } = await compactDecrypt(jwe, await importJWK(privateJwk as never, 'ECDH-ES'))
  return new TextDecoder().decode(plaintext)
}

const send = (body: Record<string, unknown>) => alice.json<Sent & Refusal>('POST', '/send', { body })

beforeAll(async () => {
  ps = await new FakePS().init()
  secret = new FakeSecret(ps)
  alice = await new Agent(ps, ALICE, RESOURCE).init()
  clearMetadataCache()
})

describe('public surface', () => {
  it('well-known is person-token with the OpenAPI vocabulary, nothing names agent.coop', async () => {
    const meta = (await (await SELF.fetch(`${RESOURCE}/.well-known/aauth-resource.json`)).json()) as Record<string, unknown>
    expect(meta.issuer).toBe(RESOURCE)
    expect(meta.access_mode).toBe('person-token')
    expect(JSON.stringify(meta).replace(/@agent\.coop/g, '')).not.toContain('agent.coop')
  })
  it('serves aauth-agent.json and an agent token Hellō would accept, cnf = AGENT_KEY', async () => {
    const doc = (await (await SELF.fetch(`${RESOURCE}/.well-known/aauth-agent.json`)).json()) as Record<string, unknown>
    expect(doc).toEqual({ issuer: RESOURCE, name: 'encrypt.aauth.dev', jwks_uri: `${RESOURCE}/.well-known/jwks.json` })
    resetAgentTokenCache()
    const jwt = await agentToken(env)
    const header = decodeProtectedHeader(jwt)
    expect(header).toMatchObject({ alg: 'Ed25519', typ: 'aa-agent+jwt' })
    const jwks = (await (await SELF.fetch(`${RESOURCE}/.well-known/jwks.json`)).json()) as { keys: Array<JsonWebKey & { kid: string; alg: string }> }
    const { alg: _a, kid: _k, key_ops: _o, ...key } = jwks.keys.find((k) => k.kid === header.kid)!
    const { payload } = await jwtVerify(jwt, await importJWK(key as never, 'Ed25519'), { issuer: RESOURCE })
    expect(payload.sub).toBe(agentSub(RESOURCE))
    expect(payload.sub).toBe('aauth:send@encrypt.aauth.dev')
    expect(payload.dwk).toBe('aauth-agent.json')
    // Required by Hellō since Wallet 2026.9.24 (#4302): 401 without one.
    expect(payload.jti).toEqual(expect.stringMatching(/^[0-9a-f-]{36}$/))
    expect((payload.cnf as { jwk: JsonWebKey }).jwk.x).toBe((JSON.parse(env.AGENT_KEY) as JsonWebKey).x)
  })
  it('OpenAPI has sendMessage: from, to, text required; resource optional, its default from DEFAULT_RESOURCE (Q6, Q7)', async () => {
    const spec = (await (await SELF.fetch(`${RESOURCE}/openapi.json`)).json()) as { paths: Record<string, Record<string, { operationId: string; requestBody: { content: Record<string, { schema: { required: string[]; properties: Record<string, { description: string }> } }> } }>> }
    const op = spec.paths['/send'].post
    expect(op.operationId).toBe('sendMessage')
    const schema = op.requestBody.content['application/json'].schema
    expect(schema.required).toEqual(['from', 'to', 'text'])
    expect(schema.properties.resource.description).toContain(env.DEFAULT_RESOURCE)
    expect(env.DEFAULT_RESOURCE).toBe(SECRET)
  })
  it('unsigned POST /send is a person-token challenge', async () => {
    const res = await SELF.fetch(`${RESOURCE}/send`, { method: 'POST', body: '{}', headers: { 'content-type': 'application/json' } })
    expect(res.status).toBe(401)
    expect(res.headers.get('aauth-requirement')).toBe('requirement=person-token')
  })
})

describe('sendMessage (6a)', () => {
  it('200: chains for a person token, getPublicKey, encrypts {text} as a compact JWE, uploadMessage; the recipient decrypts with jose', async () => {
    const bob = await secret.addRecipient(BOB)
    const { status, body } = await send({ resource: SECRET, from: FROM, to: BOB, text: 'hello from encrypt' })
    expect(status).toBe(200)
    // from and to as the messaging service shows them: its display forms pass through (3c).
    expect(body).toEqual({ id: expect.stringMatching(/^msg_/), from: 'mailto:Alice@example.com', to: 'mailto:Bob@example.com', kid: bob.kid, size: expect.any(Number), resource: SECRET })

    // The chain: one person-token request; the messaging service saw Alice's
    // directed sub for it, not her sub here, and this service's agent id (10).
    expect(ps.personTokenRequests).toBe(1)
    expect(secret.requests).toEqual(['GET /public-key', 'POST /messages'])
    expect(new Set(secret.seen)).toEqual(new Set([await ps.sub(ALICE, SECRET)]))
    expect(secret.seen[0]).not.toBe(await ps.sub(ALICE, RESOURCE))

    const m = secret.received[0]
    expect(m).toMatchObject({ from: FROM, to: BOB, kid: bob.kid, agent_id: 'aauth:send@encrypt.aauth.dev' })
    expect(m.idempotency_key).toBeUndefined()
    const parts = m.jwe.split('.')
    expect(parts).toHaveLength(5)
    expect(parts[1]).toBe('')
    expect(body.size).toBe(m.jwe.length)
    expect(decodeProtectedHeader(m.jwe)).toMatchObject({ alg: 'ECDH-ES', enc: 'A256GCM', kid: bob.kid, epk: { kty: 'EC', crv: 'P-256' } })
    // The plaintext is exactly {text}.
    expect(await decryptWithJose(bob.privateJwk, m.jwe)).toBe(JSON.stringify({ text: 'hello from encrypt' }))
  })

  it('resource is optional: the default is DEFAULT_RESOURCE (Q7)', async () => {
    const before = secret.received.length
    const { status, body } = await send({ from: FROM, to: BOB, text: 'to the default' })
    expect(status).toBe(200)
    expect(body.resource).toBe(SECRET)
    expect(secret.received).toHaveLength(before + 1)
  })

  it('from is required (Q6); from, to, text and idempotency_key are checked before any call goes out', async () => {
    const psBefore = ps.personTokenRequests
    const cases: Array<[string, Record<string, unknown>]> = [
      ['from', { to: BOB, text: 'hi' }],
      ['from', { from: 'has space@example.com', to: BOB, text: 'hi' }],
      ['to', { from: FROM, text: 'hi' }],
      ['text', { from: FROM, to: BOB }],
      ['text', { from: FROM, to: BOB, text: 42 }],
      ['idempotency_key', { from: FROM, to: BOB, text: 'hi', idempotency_key: 'k'.repeat(65) }],
    ]
    for (const [field, b] of cases) {
      const { status, body } = await send(b)
      expect(status, JSON.stringify(b)).toBe(400)
      expect(body).toMatchObject({ error: 'invalid_request', field })
    }
    expect(ps.personTokenRequests).toBe(psBefore)
  })

  it('a from that is not the caller\'s is the messaging service\'s invalid_request, passed through with step get_public_key', async () => {
    const { status, body } = await send({ from: 'mailto:not-mine@example.com', to: BOB, text: 'hi' })
    expect(status).toBe(400)
    expect(body).toMatchObject({ error: 'invalid_request', field: 'from', step: 'get_public_key', resource: SECRET })
  })

  it('an envelope layer around the fields is refused: {body: {…}} has no from (13b step 7)', async () => {
    const { status, body } = await send({ body: { from: FROM, to: BOB, text: 'hi' } })
    expect(status).toBe(400)
    expect(body).toMatchObject({ error: 'invalid_request', field: 'from' })
  })

  it('passes idempotency_key through; a replay returns the first message with replayed: true', async () => {
    const bob = secret.recipients.get(BOB)!
    const before = secret.received.length
    const first = await send({ from: 'mailto:alice@work.example', to: BOB, text: 'twice', idempotency_key: 'k-1' })
    expect(first.status).toBe(200)
    const m = secret.received[before]
    expect(m).toMatchObject({ from: 'mailto:alice@work.example', idempotency_key: 'k-1' })
    expect(JSON.parse(await decryptWithJose(bob.privateJwk, m.jwe))).toEqual({ text: 'twice' })
    const again = await send({ from: 'mailto:alice@work.example', to: BOB, text: 'twice', idempotency_key: 'k-1' })
    expect(again.status).toBe(200)
    expect(again.body).toEqual({ ...first.body, replayed: true })
    expect(secret.received).toHaveLength(before + 1)
  })

  it('404 not_connected passes through with step get_public_key', async () => {
    const { status, body } = await send({ from: FROM, to: 'mailto:stranger@example.com', text: 'hi' })
    expect(status).toBe(404)
    expect(body).toMatchObject({ error: 'not_connected', step: 'get_public_key', resource: SECRET })
  })

  it('409 recipient_has_no_key passes through with step get_public_key', async () => {
    secret.connected.add('mailto:keyless@example.com')
    const { status, body } = await send({ from: FROM, to: 'mailto:keyless@example.com', text: 'hi' })
    expect(status).toBe(409)
    expect(body).toMatchObject({ error: 'recipient_has_no_key', step: 'get_public_key' })
  })

  it('429 rate_limited passes through with step upload_message', async () => {
    secret.failNextUpload = { status: 429, error: 'rate_limited', detail: '100 messages per hour' }
    const { status, body } = await send({ from: FROM, to: BOB, text: 'hi' })
    expect(status).toBe(429)
    expect(body).toMatchObject({ error: 'rate_limited', detail: '100 messages per hour', step: 'upload_message', resource: SECRET })
  })

  it('413 too_large from the messaging service passes through with step upload_message', async () => {
    secret.failNextUpload = { status: 413, error: 'too_large' }
    const { status, body } = await send({ from: FROM, to: BOB, text: 'hi' })
    expect(status).toBe(413)
    expect(body).toMatchObject({ error: 'too_large', step: 'upload_message' })
  })

  it('413 text_too_long: over 64 KB is refused before any call goes out; 64 KB fits in a 96 KB JWE', async () => {
    const psBefore = ps.personTokenRequests
    const reqBefore = secret.requests.length
    const { status, body } = await send({ from: FROM, to: BOB, text: 'x'.repeat(MAX_PLAINTEXT) })
    expect(status).toBe(413)
    expect(body.error).toBe('text_too_long')
    expect(ps.personTokenRequests).toBe(psBefore)
    expect(secret.requests).toHaveLength(reqBefore)
    // Just under the cap goes through, and the compact JWE is within the messaging service's 96 KB (8b).
    const ok = await send({ from: FROM, to: BOB, text: 'y'.repeat(MAX_PLAINTEXT - '{"text":""}'.length) })
    expect(ok.status).toBe(200)
    expect(ok.body.size).toBeLessThanOrEqual(98_304)
    expect(ok.body.size).toBeGreaterThan(86_000)
  })

  it('attachments are refused (Q8)', async () => {
    const psBefore = ps.personTokenRequests
    const { status, body } = await send({ from: FROM, to: BOB, text: 'hi', attachments: [{ name: 'a.txt', media_type: 'text/plain', data: 'YQ==' }] })
    expect(status).toBe(400)
    expect(body.error).toBe('attachments_not_supported')
    expect(ps.personTokenRequests).toBe(psBefore)
  })

  it('resource, when given, must be an https origin', async () => {
    for (const resource of ['secret.agent.coop', 'http://secret.fake.test', 'https://secret.fake.test/', 'https://secret.fake.test/messages', 'https://u:p@secret.fake.test', null, 7]) {
      const { status, body } = await send({ resource, from: FROM, to: BOB, text: 'hi' })
      expect(status, String(resource)).toBe(400)
      expect(body).toMatchObject({ error: 'invalid_request', field: 'resource' })
    }
    expect(parseResource('https://secret.agent.coop')).toBe('https://secret.agent.coop')
    expect(parseResource('https://Secret.Agent.Coop')).toBeNull()
  })

  it('502 step person_token: the PS refusing the upstream token (wrong aud) carries the PS error code', async () => {
    ps.expectedIntermediary = 'https://other.example'
    try {
      const reqBefore = secret.requests.length
      const { status, body } = await send({ from: FROM, to: BOB, text: 'hi' })
      expect(status).toBe(502)
      expect(body).toMatchObject({ error: 'invalid_upstream_token', step: 'person_token', resource: SECRET })
      expect(secret.requests).toHaveLength(reqBefore)
    } finally {
      ps.expectedIntermediary = undefined
    }
  })

  it('a person token for another audience is refused before anything else', async () => {
    const jwt = await ps.personToken(ALICE, alice.key, 'https://other.example')
    const res = await alice.signed(jwt, 'POST', `${RESOURCE}/send`, { body: { from: FROM, to: BOB, text: 'hi' } })
    expect(res.status).toBe(401)
    expect(((await res.json()) as { error: string }).error).toBe('aud_mismatch')
  })
})

describe('the key_rotated retry (5d, Q3)', () => {
  it('a key rotated between getPublicKey and uploadMessage: fetches the key again and retries once; the message is to the new key', async () => {
    const old = secret.recipients.get(BOB)!
    const requests = secret.requests.length
    const received = secret.received.length
    secret.rotateBeforeUploads = 1
    const { status, body } = await send({ from: FROM, to: BOB, text: 'after the rotation' })
    expect(status).toBe(200)
    const latest = secret.recipients.get(BOB)!
    expect(latest.kid).not.toBe(old.kid)
    expect(body.kid).toBe(latest.kid)
    expect(secret.requests.slice(requests)).toEqual(['GET /public-key', 'POST /messages', 'GET /public-key', 'POST /messages'])
    expect(secret.received).toHaveLength(received + 1)
    const m = secret.received.at(-1)!
    expect(m.kid).toBe(latest.kid)
    expect(JSON.parse(await decryptWithJose(latest.privateJwk, m.jwe))).toEqual({ text: 'after the rotation' })
    await expect(decryptWithJose(old.privateJwk, m.jwe)).rejects.toThrow()
  })

  it('once: a second key_rotated passes through as 409 with step upload_message', async () => {
    const requests = secret.requests.length
    const received = secret.received.length
    secret.rotateBeforeUploads = 2
    const { status, body } = await send({ from: FROM, to: BOB, text: 'rotating forever' })
    expect(status).toBe(409)
    expect(body).toMatchObject({ error: 'key_rotated', kid: secret.recipients.get(BOB)!.kid, step: 'upload_message', resource: SECRET })
    expect(secret.requests.slice(requests)).toEqual(['GET /public-key', 'POST /messages', 'GET /public-key', 'POST /messages'])
    expect(secret.received).toHaveLength(received)
    expect(secret.rotateBeforeUploads).toBe(0)
  })

  it('another 409 is not retried', async () => {
    const requests = secret.requests.length
    secret.failNextUpload = { status: 409, error: 'recipient_has_no_key' }
    const { status, body } = await send({ from: FROM, to: BOB, text: 'hi' })
    expect(status).toBe(409)
    expect(body).toMatchObject({ error: 'recipient_has_no_key', step: 'upload_message' })
    expect(secret.requests.slice(requests)).toEqual(['GET /public-key', 'POST /messages'])
  })
})

describe('the encoder against the interop vectors', () => {
  for (const v of [joseVector, jwcryptoVector] as Array<{ generator: string; kid: string; public_jwk: JsonWebKey; private_jwk: JsonWebKey; plaintext: string; compact: string; protected_header: Record<string, unknown> }>) {
    it(`encrypts to the ${v.generator} vector's key as a compact JWE and its private key decrypts it (jose)`, async () => {
      const jwe = await encryptCompact(v.public_jwk, v.kid, new TextEncoder().encode(v.plaintext))
      const header = decodeProtectedHeader(jwe) as Record<string, unknown>
      expect(header.alg).toBe(v.protected_header.alg)
      expect(header.enc).toBe(v.protected_header.enc)
      expect(header.kid).toBe(v.kid)
      expect((header.epk as JsonWebKey).crv).toBe('P-256')
      // Same shape as the vector's own compact string: five parts, the second empty, the same ciphertext length.
      const [ours, theirs] = [jwe.split('.'), v.compact.split('.')]
      expect(ours.map((p) => p.length).slice(1)).toEqual(theirs.map((p) => p.length).slice(1))
      expect(await decryptWithJose(v.private_jwk, jwe)).toBe(v.plaintext)
    })
  }
  it('refuses a key that is not a public P-256 JWK', async () => {
    expect(publicP256({ kty: 'EC', crv: 'P-384', x: 'a', y: 'b' })).toBeNull()
    expect(publicP256({ ...joseVector.public_jwk, d: 'x' })).toBeNull()
    await expect(encryptCompact({ kty: 'OKP', crv: 'Ed25519', x: 'a' } as JsonWebKey, 'k', new Uint8Array(1))).rejects.toMatchObject({ code: 'invalid_recipient_key' })
  })
})
