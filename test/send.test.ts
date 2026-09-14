// encrypt.aauth.dev: sendMessage end to end against the fake PS (with the
// HTTP person_token_endpoint for the chain) and a fake messaging service at
// a non-agent.coop host, so the target resource is proven to be a
// parameter. The ciphertext that arrives is decrypted with jose using the
// recipient's private key; the encoder is also checked against the
// interop vectors' keys.
import { beforeAll, describe, expect, it } from 'vitest'
import { SELF, env } from 'cloudflare:test'
import { clearMetadataCache } from '@aauth/resource'
import { compactDecrypt, decodeProtectedHeader, importJWK, jwtVerify } from 'jose'
import { Agent, FakePS, FakeSecret, RESOURCE, SECRET } from './fake-ps'
import { agentSub, agentToken, resetAgentTokenCache } from '../src/agent-identity'
import { encryptTo, publicP256 } from '../src/jwe'
import { MAX_CIPHERTEXT, parseResource } from '../src/send'
import joseVector from '../spec/vectors/jose.json'
import jwcryptoVector from '../spec/vectors/jwcrypto.json'

let ps: FakePS
let secret: FakeSecret
let alice: Agent

const ALICE = { handle: 'alice', email: 'alice@example.com' }
const BOB = 'mailto:bob@example.com'

interface Sent { id: string; to: string; from?: string; kid: string; size: number; resource: string; replayed?: boolean }
interface Refusal { error: string; detail?: string; step?: string; resource?: string }

function b64url(bytes: Uint8Array): string {
  let s = ''
  for (const b of bytes) s += String.fromCharCode(b)
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

/** Reassemble the disassembled JWE and decrypt it with jose. */
async function decryptWithJose(privateJwk: JsonWebKey, m: { protected: string; iv: string; tag: string; blob?: Uint8Array }): Promise<string> {
  const key = await importJWK(privateJwk as never, 'ECDH-ES')
  const { plaintext } = await compactDecrypt(`${m.protected}..${m.iv}.${b64url(m.blob!)}.${m.tag}`, key)
  return new TextDecoder().decode(plaintext)
}

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
    expect((payload.cnf as { jwk: JsonWebKey }).jwk.x).toBe((JSON.parse(env.AGENT_KEY) as JsonWebKey).x)
  })
  it('OpenAPI has sendMessage with resource required', async () => {
    const spec = (await (await SELF.fetch(`${RESOURCE}/openapi.json`)).json()) as { paths: Record<string, Record<string, { operationId: string; requestBody: { content: Record<string, { schema: { required: string[] } }> } }>> }
    expect(spec.paths['/send'].post.operationId).toBe('sendMessage')
    expect(spec.paths['/send'].post.requestBody.content['application/json'].schema.required).toEqual(['resource', 'to', 'text'])
  })
  it('unsigned POST /send is a person-token challenge', async () => {
    const res = await SELF.fetch(`${RESOURCE}/send`, { method: 'POST', body: '{}', headers: { 'content-type': 'application/json' } })
    expect(res.status).toBe(401)
    expect(res.headers.get('aauth-requirement')).toBe('requirement=person-token')
  })
})

describe('sendMessage', () => {
  it('happy path: chains for a person token, fetches the key, encrypts, delivers; the recipient decrypts with jose', async () => {
    const bob = await secret.addRecipient(BOB)
    const { status, body } = await alice.json<Sent>('POST', '/send', { body: { resource: SECRET, to: BOB, text: 'hello from encrypt' } })
    expect(status).toBe(200)
    expect(body.resource).toBe(SECRET)
    expect(body.to).toBe(BOB)
    expect(body.kid).toBe(bob.kid)
    expect(body.id).toMatch(/^msg_/)

    // The chain: one person-token request with secret's agent token; the
    // fake messaging service saw Alice's directed sub for it, not her sub here.
    expect(ps.personTokenRequests).toBe(1)
    expect(secret.requests).toEqual(['GET /keys', 'POST /messages', `PUT /messages/${body.id}/blob`])
    expect(new Set(secret.seen)).toEqual(new Set([await ps.sub(ALICE, SECRET)]))
    expect(secret.seen[0]).not.toBe(await ps.sub(ALICE, RESOURCE))

    // What arrived: canonical octet-stream blob whose length equals size.
    const m = secret.received[0]
    expect(m.size).toBe(body.size)
    expect(m.blob!.byteLength).toBe(m.size)
    expect(m.blobContentType).toBe('application/octet-stream')
    expect(m.kid).toBe(bob.kid)
    expect(m.from).toBeUndefined()
    expect(m.idempotency_key).toBeUndefined()
    expect(JSON.parse(await decryptWithJose(bob.privateJwk, m))).toEqual({ text: 'hello from encrypt' })
    // The plaintext is exactly {text}: ciphertext length is the JSON length (no padding in GCM).
    expect(m.size).toBe(JSON.stringify({ text: 'hello from encrypt' }).length)
  })

  it('passes from and idempotency_key through; a replay whose blob is stored is not re-uploaded', async () => {
    const bob = secret.recipients.get(BOB)!
    const before = secret.received.length
    const first = await alice.json<Sent>('POST', '/send', { body: { resource: SECRET, to: BOB, text: 'twice', from: 'mailto:alice@work.example', idempotency_key: 'k-1' } })
    expect(first.status).toBe(200)
    const m = secret.received[before]
    expect(m.from).toBe('mailto:alice@work.example')
    expect(m.idempotency_key).toBe('k-1')
    expect(JSON.parse(await decryptWithJose(bob.privateJwk, m))).toEqual({ text: 'twice' })
    const requests = secret.requests.length
    const again = await alice.json<Sent>('POST', '/send', { body: { resource: SECRET, to: BOB, text: 'twice', from: 'mailto:alice@work.example', idempotency_key: 'k-1' } })
    expect(again.status).toBe(200)
    expect(again.body.id).toBe(first.body.id)
    expect(again.body.replayed).toBe(true)
    expect(secret.received).toHaveLength(before + 1)
    expect(secret.requests.slice(requests)).toEqual(['GET /keys', 'POST /messages'])
  })

  it('not_connected passes through verbatim', async () => {
    const { status, body } = await alice.json<Refusal>('POST', '/send', { body: { resource: SECRET, to: 'mailto:stranger@example.com', text: 'hi' } })
    expect(status).toBe(404)
    expect(body.error).toBe('not_connected')
    expect(body.step).toBe('get_keys')
    expect(body.resource).toBe(SECRET)
  })

  it('recipient_has_no_key passes through verbatim', async () => {
    secret.connected.add('mailto:keyless@example.com')
    const { status, body } = await alice.json<Refusal>('POST', '/send', { body: { resource: SECRET, to: 'mailto:keyless@example.com', text: 'hi' } })
    expect(status).toBe(409)
    expect(body.error).toBe('recipient_has_no_key')
    expect(body.step).toBe('get_keys')
  })

  it('a refusal from sendMessage at the messaging service passes through (rate_limited)', async () => {
    secret.failNextSend = { status: 429, error: 'rate_limited', detail: '100 messages per hour' }
    const { status, body } = await alice.json<Refusal>('POST', '/send', { body: { resource: SECRET, to: BOB, text: 'hi' } })
    expect(status).toBe(429)
    expect(body.error).toBe('rate_limited')
    expect(body.detail).toBe('100 messages per hour')
    expect(body.step).toBe('send_message')
  })

  it('text over 64 KB is refused before any call goes out', async () => {
    const psBefore = ps.personTokenRequests
    const reqBefore = secret.requests.length
    const { status, body } = await alice.json<Refusal>('POST', '/send', { body: { resource: SECRET, to: BOB, text: 'x'.repeat(MAX_CIPHERTEXT) } })
    expect(status).toBe(413)
    expect(body.error).toBe('text_too_long')
    expect(ps.personTokenRequests).toBe(psBefore)
    expect(secret.requests).toHaveLength(reqBefore)
    // Just under the cap goes through.
    const ok = await alice.json<Sent>('POST', '/send', { body: { resource: SECRET, to: BOB, text: 'y'.repeat(MAX_CIPHERTEXT - '{"text":""}'.length) } })
    expect(ok.status).toBe(200)
    expect(ok.body.size).toBe(MAX_CIPHERTEXT)
  })

  it('attachments are refused (D25)', async () => {
    const psBefore = ps.personTokenRequests
    const { status, body } = await alice.json<Refusal>('POST', '/send', { body: { resource: SECRET, to: BOB, text: 'hi', attachments: [{ name: 'a.txt', media_type: 'text/plain', data: 'YQ==' }] } })
    expect(status).toBe(400)
    expect(body.error).toBe('attachments_not_supported')
    expect(ps.personTokenRequests).toBe(psBefore)
  })

  it('resource must be an https origin; to and text are required', async () => {
    for (const resource of [undefined, 'secret.agent.coop', 'http://secret.fake.test', 'https://secret.fake.test/', 'https://secret.fake.test/messages', 'https://u:p@secret.fake.test']) {
      const { status, body } = await alice.json<Refusal & { field: string }>('POST', '/send', { body: { resource, to: BOB, text: 'hi' } })
      expect(status, String(resource)).toBe(400)
      expect(body.error).toBe('invalid_request')
      expect(body.field).toBe('resource')
    }
    expect(parseResource('https://secret.agent.coop')).toBe('https://secret.agent.coop')
    expect(parseResource('https://Secret.Agent.Coop')).toBeNull()
    const noTo = await alice.json<Refusal & { field: string }>('POST', '/send', { body: { resource: SECRET, text: 'hi' } })
    expect(noTo.body.field).toBe('to')
    const noText = await alice.json<Refusal & { field: string }>('POST', '/send', { body: { resource: SECRET, to: BOB } })
    expect(noText.body.field).toBe('text')
  })

  it('the PS refusing the upstream token (wrong aud) is a 502 with the PS error code', async () => {
    ps.expectedIntermediary = 'https://other.example'
    try {
      const reqBefore = secret.requests.length
      const { status, body } = await alice.json<Refusal>('POST', '/send', { body: { resource: SECRET, to: BOB, text: 'hi' } })
      expect(status).toBe(502)
      expect(body.error).toBe('invalid_upstream_token')
      expect(body.step).toBe('person_token')
      expect(secret.requests).toHaveLength(reqBefore)
    } finally {
      ps.expectedIntermediary = undefined
    }
  })

  it('a person token for another audience is refused before anything else', async () => {
    const jwt = await ps.personToken(ALICE, alice.key, 'https://other.example')
    const res = await alice.signed(jwt, 'POST', `${RESOURCE}/send`, { body: { resource: SECRET, to: BOB, text: 'hi' } })
    expect(res.status).toBe(401)
    expect(((await res.json()) as { error: string }).error).toBe('aud_mismatch')
  })
})

describe('the encoder against the interop vectors', () => {
  for (const v of [joseVector, jwcryptoVector] as Array<{ generator: string; kid: string; public_jwk: JsonWebKey; private_jwk: JsonWebKey; plaintext: string; protected_header: Record<string, unknown> }>) {
    it(`encrypts to the ${v.generator} vector's key and its private key decrypts it (jose)`, async () => {
      const env = await encryptTo(v.public_jwk, v.kid, new TextEncoder().encode(v.plaintext))
      const header = JSON.parse(new TextDecoder().decode(Uint8Array.from(atob(env.protected.replace(/-/g, '+').replace(/_/g, '/')), (c) => c.charCodeAt(0)))) as Record<string, unknown>
      expect(header.alg).toBe(v.protected_header.alg)
      expect(header.enc).toBe(v.protected_header.enc)
      expect(header.kid).toBe(v.kid)
      expect((header.epk as JsonWebKey).crv).toBe('P-256')
      expect(env.ciphertext.byteLength).toBe(new TextEncoder().encode(v.plaintext).byteLength)
      expect(await decryptWithJose(v.private_jwk, { ...env, blob: env.ciphertext })).toBe(v.plaintext)
    })
  }
  it('refuses a key that is not a public P-256 JWK', async () => {
    expect(publicP256({ kty: 'EC', crv: 'P-384', x: 'a', y: 'b' })).toBeNull()
    expect(publicP256({ ...joseVector.public_jwk, d: 'x' })).toBeNull()
    await expect(encryptTo({ kty: 'OKP', crv: 'Ed25519', x: 'a' } as JsonWebKey, 'k', new Uint8Array(1))).rejects.toMatchObject({ code: 'invalid_recipient_key' })
  })
})
