// Token revocation (AAuth Protocol -11 §Token Revocation): the PS that issued
// a token withdraws it at /aauth/revoke, signing as itself; the token is then
// refused at /send with 401 + Signature-Error revoked_jwt and
// requirement=person-token.
import { beforeAll, describe, expect, it } from 'vitest'
import { SELF } from 'cloudflare:test'
import { clearMetadataCache } from '@aauth/resource'
import { decodeJwt } from 'jose'
import { Agent, FakePS, RESOURCE, now } from './fake-ps'

const REVOKE = `${RESOURCE}/aauth/revoke`
const ALICE = { handle: 'alice', email: 'alice@example.com' }

let ps: FakePS
let otherPs: FakePS
let alice: Agent

const nameOf = (jwt: string) => {
  const { jti, exp } = decodeJwt(jwt)
  return { jti, exp }
}
const send = (jwt: string) => alice.signed(jwt, 'POST', `${RESOURCE}/send`, { body: {} })

beforeAll(async () => {
  ps = await new FakePS().init()
  otherPs = await new FakePS('https://other-ps.fake.test').init()
  alice = await new Agent(ps, ALICE, RESOURCE).init()
  clearMetadataCache()
})

describe('POST /aauth/revoke', () => {
  it('is advertised as revocation_endpoint', async () => {
    const meta = (await (await SELF.fetch(`${RESOURCE}/.well-known/aauth-resource.json`)).json()) as Record<string, unknown>
    expect(meta.revocation_endpoint).toBe(REVOKE)
  })

  it('the PS revokes a person token it issued; the token is then refused with revoked_jwt and requirement=person-token', async () => {
    const pt = await ps.personToken(ALICE, alice.key)
    expect((await send(pt)).status).toBe(400) // past auth: the empty body is the refusal

    const res = await ps.revoke(REVOKE, nameOf(pt))
    expect(res.status).toBe(200)
    expect(await res.text()).toBe('') // no "found" / "not found"
    expect(res.headers.get('cache-control')).toBe('no-store')

    const after = await send(pt)
    expect(after.status).toBe(401)
    expect(after.headers.get('signature-error')).toBe('error=revoked_jwt')
    expect(after.headers.get('aauth-requirement')).toBe('requirement=person-token')
    expect(((await after.json()) as { error: string }).error).toBe('revoked_jwt')

    // Per token: a fresh one from the same PS still gets through.
    expect((await send(await ps.personToken(ALICE, alice.key))).status).toBe(400)
  })

  it('a revocation by another server names a different token: (iss, jti) is the key', async () => {
    const pt = await ps.personToken(ALICE, alice.key)
    // other-ps is not in REVOCATION_ISSUERS: refused before anything is recorded.
    const res = await otherPs.revoke(REVOKE, nameOf(pt))
    expect(res.status).toBe(403)
    expect(res.headers.get('signature-error')).toBeNull()
    expect(((await res.json()) as { error: string }).error).toBe('unsupported_iss')
    expect((await send(pt)).status).toBe(400)
  })

  it('answers 200 for a token it never saw and for one already past its exp', async () => {
    expect((await ps.revoke(REVOKE, { jti: `never-${crypto.randomUUID()}`, exp: now() + 300 })).status).toBe(200)
    expect((await ps.revoke(REVOKE, { jti: 'long-dead', exp: now() - 3600 })).status).toBe(200)
  })

  it('refuses a request that is not a server signing as itself', async () => {
    const body = JSON.stringify({ jti: 'x', exp: now() + 60 })
    let res = await SELF.fetch(REVOKE, { method: 'POST', headers: { 'content-type': 'application/json' }, body })
    expect(res.status).toBe(401)
    expect(((await res.json()) as { error: string }).error).toBe('signature_required')
    expect(res.headers.get('accept-signature-scheme')).toContain('jwks_uri')

    // An agent presenting a person token.
    res = await alice.signed(await ps.personToken(ALICE, alice.key), 'POST', REVOKE, { body: { jti: 'x', exp: now() + 60 } })
    expect(res.status).toBe(401)
    expect(res.headers.get('signature-error')).toBe('error=unsupported_scheme')
  })

  it('requires the signature to cover content-type (httpsig always covers content-digest on a body)', async () => {
    const res = await ps.revoke(REVOKE, { jti: 'x', exp: now() + 60 }, ['@method', '@authority', '@path', 'signature-key'])
    expect(res.status).toBe(401)
    expect(res.headers.get('signature-error')).toContain('invalid_input')
    expect(((await res.json()) as { detail: string }).detail).toBe('signature must cover content-type')
  })

  it('invalid_request for a body that does not name a token', async () => {
    for (const body of [{ jti: 'x' }, { exp: now() + 60 }, { jti: 'x', exp: 'soon' }, [], null]) {
      const res = await ps.revoke(REVOKE, body)
      expect(res.status, JSON.stringify(body)).toBe(400)
      expect(((await res.json()) as { error: string }).error).toBe('invalid_request')
    }
  })
})
