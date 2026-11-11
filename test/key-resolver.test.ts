// Key discovery through one @hellocoop/httpsig key resolver (src/key-resolver.ts):
// every metadata and JWKS fetch is one aauth.encrypt.key_fetch event, the
// token issuer's keys and a jwks_uri-scheme signer's keys share one cache,
// and a redirect is refused under workerd.
import { beforeAll, describe, expect, it, vi } from 'vitest'
import { Agent, FakePS, RESOURCE, mockRoute, now } from './fake-ps'
import { clearKeyCache } from '../src/key-resolver'

const ALICE = { handle: 'alice', email: 'alice@example.com' }

let ps: FakePS
let alice: Agent

/** Run `fn`, returning the key_fetch events it emitted (console.log JSON, in the request). */
async function keyFetches(fn: () => Promise<unknown>): Promise<Array<Record<string, any>>> {
  const events: Array<Record<string, any>> = []
  const spy = vi.spyOn(console, 'log').mockImplementation((line: unknown) => {
    try {
      const o = JSON.parse(String(line))
      if (o?.event === 'aauth.encrypt.key_fetch') events.push(o)
    } catch {
      /* not one of ours */
    }
  })
  try {
    await fn()
  } finally {
    spy.mockRestore()
  }
  return events
}

const send = (who: Agent, jwt: string) => who.signed(jwt, 'POST', `${RESOURCE}/send`, { body: {} })

beforeAll(async () => {
  ps = await new FakePS('https://keys-ps.fake.test').init()
  alice = await new Agent(ps, ALICE, RESOURCE).init()
  clearKeyCache()
})

describe('key discovery', () => {
  it('a cold lookup is one key_fetch event per document fetched; the next request fetches nothing', async () => {
    const events = await keyFetches(async () => {
      expect((await send(alice, await ps.personToken(ALICE, alice.key))).status).toBe(400) // past auth
    })
    expect(events).toHaveLength(2)
    expect(events[0]).toMatchObject({
      service: 'encrypt', level: 30, route: '/send',
      url: `${ps.iss}/.well-known/aauth-person.json`, doc: 'metadata', id: ps.iss, dwk: 'aauth-person.json',
      reason: 'cold', ok: true, status: 200, duration_ms: expect.any(Number), ttl_ms: expect.any(Number),
      msg: `metadata fetch ok (cold): ${ps.iss}/.well-known/aauth-person.json`,
    })
    expect(events[1]).toMatchObject({ url: `${ps.iss}/jwks.json`, doc: 'jwks', reason: 'cold', ok: true, status: 200, level: 30 })

    const again = await keyFetches(async () => {
      expect((await send(alice, await ps.personToken(ALICE, alice.key))).status).toBe(400)
    })
    expect(again).toEqual([])
  })

  it('a revocation signed through the jwks_uri scheme uses the keys the token lookup cached', async () => {
    const events = await keyFetches(async () => {
      // keys-ps is not in REVOCATION_ISSUERS: 403 after the signature verified.
      expect((await ps.revoke(`${RESOURCE}/aauth/revoke`, { jti: 'x', exp: now() + 60 })).status).toBe(403)
    })
    expect(events).toEqual([])
  })

  it('a redirect is refused, logged at level 40, and not refetched inside the floor', async () => {
    const moved = await new FakePS('https://moved-ps.fake.test').init()
    mockRoute(`${moved.iss}/.well-known/aauth-person.json`, () => new Response(null, { status: 302, headers: { location: `${ps.iss}/.well-known/aauth-person.json` } }))
    const bob = await new Agent(moved, { handle: 'bob', email: 'bob@example.com' }, RESOURCE).init()

    let res!: Response
    const events = await keyFetches(async () => {
      res = await send(bob, await moved.personToken(bob.person, bob.key))
    })
    expect(res.status).toBe(401)
    expect(((await res.json()) as { error: string }).error).toBe('metadata_fetch_failed')
    expect(events).toHaveLength(1)
    expect(events[0]).toMatchObject({ level: 40, url: `${moved.iss}/.well-known/aauth-person.json`, doc: 'metadata', reason: 'cold', ok: false, status: 302 })
    expect(events[0].msg).toBe(`metadata fetch failed (cold): ${moved.iss}/.well-known/aauth-person.json`)

    const again = await keyFetches(async () => {
      expect((await send(bob, await moved.personToken(bob.person, bob.key))).status).toBe(401)
    })
    expect(again).toEqual([])
  })
})
