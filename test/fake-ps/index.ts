// A fake Person Server for the test build, copied from
// secret-agent-coop/service/test/fake-ps (a shared package is increment 7).
// Runs inside the Workers test isolate: issues person tokens with a sub
// directed per audience, exchanges resource tokens for auth tokens, and
// serves an HTTP person_token_endpoint for call chaining: it verifies the
// intermediary's signed request and agent token (against the issuer's
// aauth-agent.json → jwks_uri, through SELF), verifies the upstream_token,
// and issues a person token for the requested resource with no
// interaction. Its documents are served through a mocked global fetch.
//
// Also here: a fake messaging service at SECRET (deliberately not an
// agent.coop host: the Worker under test must take the target from the
// request or from DEFAULT_RESOURCE) with getPublicKey and uploadMessage,
// verifying the signature and the chained person token and recording what
// arrived.
//
// Also here: an Agent that plays the AAuth MCP against the Worker under
// test — signs requests with RFC 9421 (jwt scheme) and follows
// AAuth-Requirement challenges the way @aauth/proxy does.

import { SELF } from 'cloudflare:test'
import { calculateThumbprint, fetch as httpsigFetch, verify as httpsigVerify } from '@hellocoop/httpsig'
import { decodeJwt, decodeProtectedHeader, importJWK, jwtVerify, SignJWT } from 'jose'
import { parseRequirementHeader } from '@aauth/protocol'

export const PS = 'https://ps.fake.test'
/** the Worker under test */
export const RESOURCE = 'https://encrypt.aauth.dev'
/** the fake messaging service in the outbound mock */
export const SECRET = 'https://secret.fake.test'

export interface TestKey {
  privateKey: CryptoKey
  privateJwk: JsonWebKey
  publicJwk: JsonWebKey & { kid: string }
}

export async function generateEd25519(): Promise<TestKey> {
  const pair = (await crypto.subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify'])) as CryptoKeyPair
  const privateJwk = (await crypto.subtle.exportKey('jwk', pair.privateKey)) as JsonWebKey & { d?: string; key_ops?: string[]; ext?: boolean }
  privateJwk.alg = 'Ed25519'
  const { d: _d, key_ops: _ko, ext: _ext, ...pub } = privateJwk
  const publicJwk = { ...pub, key_ops: ['verify'], alg: 'Ed25519' }
  const kid = await calculateThumbprint(publicJwk)
  return { privateKey: pair.privateKey, privateJwk, publicJwk: { ...publicJwk, kid } }
}

export const now = () => Math.floor(Date.now() / 1000)

function b64url(bytes: Uint8Array): string {
  let s = ''
  for (const b of bytes) s += String.fromCharCode(b)
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

export function cnfJwk(key: TestKey): JsonWebKey {
  const { kid: _kid, key_ops: _ko, ...jwk } = key.publicJwk
  return jwk
}

// ── Outbound fetch mock ──
// Tests and the worker under test share one isolate, so replacing
// globalThis.fetch serves the PS's discovery documents. SELF.fetch and
// bindings are unaffected.
type RouteHandler = (req: Request) => Response | Promise<Response>
const routes = new Map<string, RouteHandler>()
/** handlers keyed by a URL prefix, for paths with ids and queries */
const prefixRoutes = new Map<string, RouteHandler>()
let installed = false
export function installMockFetch(): void {
  if (installed) return
  installed = true
  globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const req = new Request(input, init)
    const url = new URL(req.url)
    const handler = routes.get(req.url) ?? routes.get(url.origin + url.pathname) ?? [...prefixRoutes.entries()].find(([p]) => req.url.startsWith(p))?.[1]
    if (!handler) throw new Error(`unmocked outbound fetch: ${req.url}`)
    return handler(req)
  }) as typeof fetch
}

/** RFC 9421 verification of a mocked outbound request, jwt scheme. */
async function verifySigned(req: Request, opts: { requireContentDigest?: boolean } = {}) {
  const url = new URL(req.url)
  const body = req.method === 'GET' || req.method === 'HEAD' ? undefined : new Uint8Array(await req.arrayBuffer())
  const sig = await httpsigVerify(
    { method: req.method, authority: url.host, path: url.pathname, query: url.search ? url.search.slice(1) : undefined, headers: req.headers, ...(body ? { body } : {}) },
    opts,
  )
  return { sig, body }
}

const problem = (status: number, error: string, detail: string) =>
  Response.json({ error, detail }, { status, headers: { 'content-type': 'application/problem+json' } })

// ── The fake PS ──

export interface Person {
  /** stable handle inside the fake PS; subs are derived per audience */
  handle: string
  email: string
  name?: string
}

export class FakePS {
  private key!: TestKey
  private issued = new Set<string>()
  /** every directed sub this PS has minted, back to the person (Hellō has its own record) */
  private subs = new Map<string, Person>()
  /** POSTs to the HTTP person_token_endpoint (the chain), for idempotency tests */
  personTokenRequests = 0
  /** the last agent token an intermediary presented at the person_token_endpoint */
  lastAgentToken?: string
  /** when set, the upstream token's aud must equal this instead of the agent token's iss (to force invalid_upstream_token) */
  expectedIntermediary?: string

  /** A second instance with another iss plays an issuer secret does not trust for email. */
  constructor(readonly iss: string = PS) {}

  async init(): Promise<this> {
    this.key = await generateEd25519()
    installMockFetch()
    routes.set(`${this.iss}/aauth/token/person`, (req) => this.personTokenEndpoint(req))
    routes.set(`${this.iss}/.well-known/aauth-person.json`, () =>
      Response.json({
        issuer: this.iss,
        jwks_uri: `${this.iss}/jwks.json`,
        person_token_endpoint: `${this.iss}/aauth/token/person`,
        auth_token_endpoint: `${this.iss}/aauth/token/auth`,
        scopes_supported: ['email', 'profile'],
        claims_supported: ['sub', 'email', 'name'],
      }),
    )
    routes.set(`${this.iss}/jwks.json`, () => Response.json({ keys: [this.key.publicJwk] }))
    return this
  }

  /** Pairwise pseudonymous sub per audience (protocol §Directed Identifiers). */
  async sub(person: Person, aud: string): Promise<string> {
    const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(`${person.handle}|${aud}`))
    const sub = b64url(new Uint8Array(digest))
    this.subs.set(sub, person)
    return sub
  }

  private async publicKey() {
    const { alg: _a, kid: _k, key_ops: _o, ...jwk } = this.key.publicJwk as JsonWebKey & { alg?: string; kid?: string; key_ops?: string[] }
    return importJWK(jwk as never, 'Ed25519')
  }

  /**
   * POST /aauth/token/person over HTTP (D26, call chaining only; agents in
   * these tests get their person tokens in-process). Mirrors what Hellō
   * checks (Wallet svr/src/aauth/verify-upstream-token.js): the signed
   * request, the agent token against the issuer's aauth-agent.json →
   * jwks_uri, then the upstream token: issued by this PS, person or auth
   * typ, aud equal to the agent token's iss, not expired. The person is the
   * one behind the upstream sub. Issues a person token for body.resource
   * with cnf = the agent token's key. No interaction.
   */
  private async personTokenEndpoint(req: Request): Promise<Response> {
    this.personTokenRequests++
    if (req.method !== 'POST') return problem(405, 'method_not_allowed', 'POST only')
    const { sig, body } = await verifySigned(req, { requireContentDigest: true })
    if (!sig.verified) return problem(401, 'signature_verification_failed', sig.error ?? 'bad signature')
    if (sig.keyType !== 'jwt' || !sig.jwt) return problem(401, 'invalid_agent_token', 'Signature-Key must be sig=jwt')
    const agentJwt = sig.jwt.raw
    const header = decodeProtectedHeader(agentJwt)
    if (header.typ !== 'aa-agent+jwt' || header.alg !== 'Ed25519' || typeof header.kid !== 'string') return problem(401, 'invalid_agent_token', `header typ=${String(header.typ)} alg=${String(header.alg)} kid=${String(header.kid)}`)
    const agent = decodeJwt(agentJwt) as Record<string, unknown>
    if (typeof agent.iss !== 'string' || agent.dwk !== 'aauth-agent.json' || typeof agent.sub !== 'string' || !/^aauth:[A-Za-z0-9\-_+.]+@[^@\s]+$/.test(agent.sub)) {
      return problem(401, 'invalid_agent_token', 'iss, dwk aauth-agent.json, and sub aauth:local@domain are required')
    }
    // Hellō requires jti on an agent token since Wallet 2026.9.24 (#4302): 401 without one.
    if (typeof agent.jti !== 'string' || !agent.jti) return problem(401, 'invalid_agent_token', 'jti required')
    const cnf = (agent.cnf as { jwk?: JsonWebKey } | undefined)?.jwk
    if (!cnf) return problem(401, 'invalid_agent_token', 'cnf.jwk required')
    // The issuer's agent document and JWKS, through SELF: the issuer is the Worker under test.
    const doc = await SELF.fetch(`${agent.iss}/.well-known/aauth-agent.json`)
    if (doc.status !== 200) return problem(401, 'invalid_agent_token', `no aauth-agent.json at ${agent.iss}`)
    const { jwks_uri } = (await doc.json()) as { jwks_uri: string }
    const jwks = (await (await SELF.fetch(jwks_uri)).json()) as { keys: Array<JsonWebKey & { kid?: string; alg?: string }> }
    const key = jwks.keys.find((k) => k.kid === header.kid)
    if (!key) return problem(401, 'invalid_agent_token', `kid ${header.kid} not at ${jwks_uri}`)
    const { alg: _a, kid: _k, key_ops: _o, ...importable } = key
    try {
      await jwtVerify(agentJwt, await importJWK(importable as never, 'Ed25519'), { issuer: agent.iss })
    } catch (err) {
      return problem(401, 'invalid_agent_token', `signature: ${String(err)}`)
    }
    this.lastAgentToken = agentJwt

    const text = new TextDecoder().decode(body ?? new Uint8Array())
    let params: Record<string, unknown>
    try {
      params = JSON.parse(text) as Record<string, unknown>
    } catch {
      return problem(400, 'invalid_request', 'JSON body required')
    }
    if (typeof params.resource !== 'string') return problem(400, 'invalid_request', 'resource required')
    if (typeof params.upstream_token !== 'string') return problem(400, 'invalid_request', 'this fake only serves chained requests (upstream_token)')
    if (params.mission_s256) return problem(400, 'invalid_request', 'mission_s256 must not accompany upstream_token')

    // The upstream token.
    let upstream: Record<string, unknown>
    try {
      upstream = (await jwtVerify(params.upstream_token, await this.publicKey(), { issuer: this.iss })).payload as Record<string, unknown>
    } catch (err) {
      return problem(400, 'invalid_upstream_token', `not issued by this PS or expired: ${String(err)}`)
    }
    const upstreamTyp = decodeProtectedHeader(params.upstream_token).typ
    if (upstreamTyp !== 'aa-person+jwt' && upstreamTyp !== 'aa-auth+jwt') return problem(400, 'invalid_upstream_token', `typ ${String(upstreamTyp)}`)
    const mustEqual = this.expectedIntermediary ?? agent.iss
    if (upstream.aud !== mustEqual) return problem(400, 'invalid_upstream_token', `aud ${String(upstream.aud)} is not the intermediary ${mustEqual}`)
    const person = typeof upstream.sub === 'string' ? this.subs.get(upstream.sub) : undefined
    if (!person) return problem(400, 'invalid_upstream_token', 'unknown sub')

    // Hellō puts the agent the token is issued to on person tokens for the
    // messaging service (Wallet passthrough-claims.js): here, the intermediary.
    const personToken = await this.sign('aa-person+jwt', {
      iss: this.iss, dwk: 'aauth-person.json', aud: params.resource, sub: await this.sub(person, params.resource), cnf: { jwk: cnf }, agent_id: agent.sub,
    }, 600)
    return Response.json({ person_token: personToken, expires_in: 600 })
  }

  /** Verify a person token this PS issued, for the fake decrypt. */
  async verifyPersonToken(jwt: string, aud: string): Promise<Record<string, unknown>> {
    if (decodeProtectedHeader(jwt).typ !== 'aa-person+jwt') throw new Error('not a person token')
    return (await jwtVerify(jwt, await this.publicKey(), { issuer: this.iss, audience: aud })).payload as Record<string, unknown>
  }

  private async sign(typ: string, claims: Record<string, unknown>, lifetime: number): Promise<string> {
    const t = now()
    const jti = b64url(crypto.getRandomValues(new Uint8Array(16)))
    this.issued.add(jti)
    return new SignJWT({ iat: t, exp: t + lifetime, jti, ...claims })
      .setProtectedHeader({ alg: 'Ed25519', typ, kid: this.key.publicJwk.kid } as never)
      .sign(this.key.privateKey)
  }

  async personToken(person: Person, agent: TestKey, aud = RESOURCE, overrides: Record<string, unknown> = {}): Promise<string> {
    return this.sign('aa-person+jwt', {
      iss: this.iss, dwk: 'aauth-person.json', aud, sub: await this.sub(person, aud), cnf: { jwk: cnfJwk(agent) }, ...overrides,
    }, 600)
  }

  /**
   * POST /aauth/token/auth, in-process. Verifies the resource token against
   * the resource's JWKS (fetched through SELF), checks presented_jti, then
   * issues an auth token for the requested scope. Auto-approves.
   */
  async exchange(person: Person, agent: TestKey, resourceToken: string, presentedToken: string): Promise<string> {
    const header = decodeProtectedHeader(resourceToken)
    if (header.typ !== 'aa-resource+jwt') throw new Error(`fake this.iss: resource token typ ${header.typ}`)
    const rt = decodeJwt(resourceToken) as Record<string, unknown>
    if (rt.aud !== this.iss) throw new Error(`fake this.iss: resource token aud ${String(rt.aud)} is not me`)
    if (rt.ps !== this.iss) throw new Error('fake this.iss: resource token ps is not me')
    const jwksRes = await SELF.fetch(`${String(rt.iss)}/.well-known/jwks.json`)
    const jwks = (await jwksRes.json()) as { keys: JsonWebKey[] }
    const jwk = jwks.keys.find((k) => (k as { kid?: string }).kid === header.kid) ?? jwks.keys[0]
    const { alg: _a, ...importable } = jwk as JsonWebKey & { alg?: string }
    await jwtVerify(resourceToken, await importJWK(importable as never, 'Ed25519'), { audience: this.iss })
    const presented = decodeJwt(presentedToken) as Record<string, unknown>
    if (presented.jti !== rt.presented_jti) throw new Error('fake this.iss: presented_jti mismatch')
    if (presented.sub !== rt.sub) throw new Error('fake this.iss: sub mismatch')
    const agentJkt = await calculateThumbprint(cnfJwk(agent))
    if (rt.agent_jkt !== agentJkt) throw new Error('fake this.iss: agent_jkt mismatch')

    const scope = String(rt.scope ?? '')
    const claims: Record<string, unknown> = {
      iss: this.iss, dwk: 'aauth-person.json', aud: rt.iss, ps: this.iss, sub: rt.sub, cnf: { jwk: cnfJwk(agent) }, scope,
    }
    if (scope.split(/\s+/).includes('email')) {
      // login_hint selects an address the person holds; otherwise the person
      // "picks" their default. A hint for an address they do not hold is
      // ignored, as Hellō would prompt to verify it and we cannot.
      const hint = typeof rt.login_hint === 'string' ? rt.login_hint.toLowerCase() : undefined
      const held = [person.email, ...(person.altEmails ?? [])].map((e) => e.toLowerCase())
      claims.email = hint && held.includes(hint) ? hint : person.email
      claims.email_verified = true
    }
    if (scope.split(/\s+/).includes('profile') && person.name) claims.name = person.name
    return this.sign('aa-auth+jwt', claims, 3600)
  }
}

export interface Person {
  altEmails?: string[]
}

// ── The fake messaging service ──
// What encrypt chains to. Verifies the signature and the chained person
// token (issued by the fake PS, aud SECRET, cnf = the signing key), then
// behaves like secret.agent.coop's getPublicKey and uploadMessage (plan
// read-send-services sections 4b, 5a) for a small in-memory world:
// `recipients` with one latest key each, `connected` addresses, `mine` the
// sender's addresses. rotate() replaces a recipient's key, so the next
// upload to the old kid is 409 key_rotated.

export interface RecipientKey {
  kid: string
  alg: 'ECDH-ES'
  jwk: JsonWebKey
  privateJwk: JsonWebKey
}
export interface ReceivedMessage {
  id: string
  from: string
  to: string
  jwe: string
  kid: string
  idempotency_key?: string
  /** the sub and agent_id the chained person token carried */
  sub: string
  agent_id: unknown
}

const MAX_JWE = 98_304
/** the display form the fake shows for any address: what secret does with identifiers.email */
const display = (address: string) => address.replace(/^mailto:(.)/i, (_m, c: string) => `mailto:${c.toUpperCase()}`)

export class FakeSecret {
  readonly origin = SECRET
  recipients = new Map<string, RecipientKey>()
  /** every private key a recipient has had, by kid: a read service keeps them all */
  privateKeys = new Map<string, JsonWebKey>()
  connected = new Set<string>()
  /** the sender's verified addresses, lowercased */
  mine = new Set<string>(['mailto:alice@example.com', 'mailto:alice@work.example'])
  received: ReceivedMessage[] = []
  /** "METHOD path" of every authenticated request, in order */
  requests: string[] = []
  /** subs seen on chained person tokens */
  seen: string[] = []
  /** the next uploadMessage answers with this */
  failNextUpload?: { status: number; error: string; detail?: string }
  /** rotate the recipient's key this many times, each just before an upload is checked: the race 5d describes */
  rotateBeforeUploads = 0
  private counter = 0

  constructor(readonly ps: FakePS) {
    installMockFetch()
    routes.set(`${SECRET}/public-key`, (req) => this.getPublicKey(req))
    routes.set(`${SECRET}/messages`, (req) => this.uploadMessage(req))
  }

  private async mint(): Promise<RecipientKey> {
    const pair = (await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits'])) as CryptoKeyPair
    const priv = (await crypto.subtle.exportKey('jwk', pair.privateKey)) as JsonWebKey
    const jwk: JsonWebKey = { kty: 'EC', crv: 'P-256', x: priv.x, y: priv.y }
    const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(JSON.stringify({ crv: 'P-256', kty: 'EC', x: jwk.x, y: jwk.y })))
    const key: RecipientKey = { kid: b64url(new Uint8Array(digest)), alg: 'ECDH-ES', jwk, privateJwk: { ...jwk, d: priv.d } }
    this.privateKeys.set(key.kid, key.privateJwk)
    return key
  }

  /** A connected person with a key. Returns the key so tests can decrypt. */
  async addRecipient(address: string): Promise<RecipientKey> {
    const key = await this.mint()
    this.recipients.set(address.toLowerCase(), key)
    this.connected.add(address.toLowerCase())
    return key
  }

  /** The recipient rotated: a new latest key; the old kid is refused from now on. */
  async rotate(address: string): Promise<RecipientKey> {
    const key = await this.mint()
    this.recipients.set(address.toLowerCase(), key)
    return key
  }

  private async auth(req: Request): Promise<{ sub: string; agent_id: unknown; body?: Uint8Array } | Response> {
    const { sig, body } = await verifySigned(req)
    if (!sig.verified) return problem(401, 'signature_verification_failed', sig.error ?? 'bad signature')
    if (sig.keyType !== 'jwt' || !sig.jwt) return problem(401, 'person_token_required', 'sig=jwt required')
    let claims: Record<string, unknown>
    try {
      claims = await this.ps.verifyPersonToken(sig.jwt.raw, SECRET)
    } catch (err) {
      return problem(401, 'invalid_token', String(err))
    }
    const cnf = (claims.cnf as { jwk?: JsonWebKey } | undefined)?.jwk
    if (!cnf || (await calculateThumbprint(cnf)) !== sig.thumbprint) return problem(401, 'cnf_mismatch', 'the request is not signed with the token\'s key')
    const url = new URL(req.url)
    this.requests.push(`${req.method} ${url.pathname}`)
    this.seen.push(String(claims.sub))
    return { sub: String(claims.sub), agent_id: claims.agent_id, body }
  }

  private async getPublicKey(req: Request): Promise<Response> {
    const a = await this.auth(req)
    if (a instanceof Response) return a
    const q = new URL(req.url).searchParams
    const from = (q.get('from') ?? '').toLowerCase()
    const to = (q.get('to') ?? '').toLowerCase()
    if (!this.mine.has(from)) return Response.json({ error: 'invalid_request', field: 'from', detail: 'from is required and must be one of your verified addresses' }, { status: 400 })
    if (!this.connected.has(to)) return Response.json({ error: 'not_connected', detail: 'no connection with that address' }, { status: 404 })
    const key = this.recipients.get(to)
    if (!key) return Response.json({ error: 'recipient_has_no_key', detail: 'the recipient has no public key yet' }, { status: 409 })
    return Response.json({ from: display(from), to: display(to), kid: key.kid, alg: key.alg, jwk: key.jwk })
  }

  private async uploadMessage(req: Request): Promise<Response> {
    const a = await this.auth(req)
    if (a instanceof Response) return a
    if (!(req.headers.get('content-type') ?? '').startsWith('application/json')) return problem(400, 'invalid_json', 'application/json required')
    if (this.failNextUpload) {
      const f = this.failNextUpload
      this.failNextUpload = undefined
      return Response.json({ error: f.error, detail: f.detail ?? f.error }, { status: f.status })
    }
    const m = JSON.parse(new TextDecoder().decode(a.body)) as Record<string, unknown>
    if (typeof m.idempotency_key === 'string') {
      const prior = this.received.find((r) => r.idempotency_key === m.idempotency_key && r.sub === a.sub)
      if (prior) return Response.json({ id: prior.id, from: display(prior.from), to: display(prior.to), kid: prior.kid, size: prior.jwe.length, replayed: true })
    }
    if (typeof m.jwe !== 'string') return Response.json({ error: 'invalid_jwe', detail: 'jwe must be a compact JWE string' }, { status: 400 })
    if (m.jwe.length > MAX_JWE) return Response.json({ error: 'too_large' }, { status: 413 })
    const parts = m.jwe.split('.')
    if (parts.length !== 5 || parts[1] !== '') return Response.json({ error: 'invalid_jwe', detail: 'not compact' }, { status: 400 })
    const header = JSON.parse(new TextDecoder().decode(b64urlDecode(parts[0]))) as Record<string, unknown>
    if (header.alg !== 'ECDH-ES' || header.enc !== 'A256GCM' || typeof header.kid !== 'string' || !header.epk) return Response.json({ error: 'invalid_jwe', detail: 'header' }, { status: 400 })
    const from = String(m.from ?? '').toLowerCase()
    const to = String(m.to ?? '').toLowerCase()
    if (!this.mine.has(from)) return Response.json({ error: 'invalid_request', field: 'from' }, { status: 400 })
    if (!this.connected.has(to)) return Response.json({ error: 'not_connected' }, { status: 404 })
    if (this.rotateBeforeUploads > 0) {
      this.rotateBeforeUploads--
      await this.rotate(to)
    }
    const key = this.recipients.get(to)
    if (!key) return Response.json({ error: 'recipient_has_no_key' }, { status: 409 })
    if (header.kid !== key.kid) return Response.json({ error: 'key_rotated', detail: "kid is not the recipient's latest key; call getPublicKey again", kid: key.kid }, { status: 409 })
    const id = `msg_fake${String(++this.counter).padStart(20, '0')}_000`
    const rec: ReceivedMessage = { id, from, to, jwe: m.jwe, kid: key.kid, idempotency_key: typeof m.idempotency_key === 'string' ? m.idempotency_key : undefined, sub: a.sub, agent_id: a.agent_id }
    this.received.push(rec)
    const now = Date.now()
    return Response.json({ id, from: display(from), to: display(to), kid: key.kid, size: m.jwe.length, created_at: new Date(now).toISOString(), expires_at: new Date(now + 30 * 86_400_000).toISOString() }, { status: 201 })
  }
}

function b64urlDecode(str: string): Uint8Array {
  const padded = str + '='.repeat((4 - (str.length % 4)) % 4)
  const bin = atob(padded.replace(/-/g, '+').replace(/_/g, '/'))
  const out = new Uint8Array(bin.length)
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i)
  return out
}

// ── The agent (plays the AAuth MCP) ──

export interface CallOptions {
  body?: unknown // object → JSON; string / Uint8Array sent as-is
  contentType?: string
  accept?: string
  headers?: Record<string, string>
  /** start with an auth token instead of a person token (default person) */
  cred?: { kind: 'person' } | { kind: 'auth'; jwt: string }
}

export class Agent {
  key!: TestKey
  lastAuthToken?: string

  constructor(readonly ps: FakePS, readonly person: Person, readonly resource = RESOURCE) {}

  async init(): Promise<this> {
    this.key = await generateEd25519()
    return this
  }

  async signed(jwt: string, method: string, url: string, opts: CallOptions): Promise<Response> {
    let body: string | Uint8Array | undefined
    const headers: Record<string, string> = { ...(opts.headers ?? {}) }
    if (opts.body !== undefined) {
      if (typeof opts.body === 'string' || opts.body instanceof Uint8Array) {
        body = opts.body
        headers['content-type'] = opts.contentType ?? (typeof opts.body === 'string' ? 'text/plain' : 'application/octet-stream')
      } else {
        body = JSON.stringify(opts.body)
        headers['content-type'] = opts.contentType ?? 'application/json'
      }
    }
    if (opts.accept) headers.accept = opts.accept
    const { headers: signedHeaders } = await httpsigFetch(url, {
      dryRun: true,
      method,
      headers,
      ...(body !== undefined ? { body } : {}),
      signingKey: this.key.privateJwk,
      signatureKey: { type: 'jwt', jwt },
    })
    return SELF.fetch(url, { method, headers: signedHeaders as HeadersInit, ...(body !== undefined ? { body: body as BodyInit } : {}) })
  }

  /** One call with the requirement loop: person token → (auth-token challenge → exchange → retry). */
  async call(method: string, path: string, opts: CallOptions = {}): Promise<Response> {
    const url = `${this.resource}${path}`
    let jwt = opts.cred?.kind === 'auth' ? opts.cred.jwt : await this.ps.personToken(this.person, this.key, this.resource)
    for (let round = 0; round < 3; round++) {
      const res = await this.signed(jwt, method, url, opts)
      const header = res.headers.get('aauth-requirement')
      if (!header) return res
      const req = parseRequirementHeader(header)
      if (!req) return res
      if (req.requirement === 'auth-token' && req.resourceToken) {
        const authToken = await this.ps.exchange(this.person, this.key, req.resourceToken, jwt)
        this.lastAuthToken = authToken
        jwt = authToken
        continue
      }
      if (req.requirement === 'person-token') {
        jwt = await this.ps.personToken(this.person, this.key, this.resource)
        continue
      }
      return res
    }
    throw new Error('requirement loop exceeded')
  }

  async json<T = Record<string, unknown>>(method: string, path: string, opts: CallOptions = {}): Promise<{ status: number; body: T; res: Response }> {
    const res = await this.call(method, path, opts)
    const text = await res.text()
    let body: T
    try {
      body = JSON.parse(text) as T
    } catch {
      body = text as unknown as T
    }
    return { status: res.status, body, res }
  }
}
