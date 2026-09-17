// Section 12c: openapi.json and /.well-known/aauth-resource.json go out
// with Cache-Control: public, max-age=300 and an ETag that is the SHA-256 of
// the body; a matching If-None-Match is a 304 with no body.
import { describe, expect, it } from 'vitest'
import { SELF } from 'cloudflare:test'

const ORIGIN = 'https://encrypt.aauth.dev'

async function sha256Hex(text: string): Promise<string> {
  const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(text)))
  return [...digest].map((b) => b.toString(16).padStart(2, '0')).join('')
}

describe('Cache-Control on the documents (12c)', () => {
  for (const path of ['/openapi.json', '/.well-known/aauth-resource.json']) {
    it(`${path}: public, max-age=300 and ETag = "<sha-256 of the body>"`, async () => {
      const res = await SELF.fetch(`${ORIGIN}${path}`)
      expect(res.status).toBe(200)
      expect(res.headers.get('cache-control')).toBe('public, max-age=300')
      expect(res.headers.get('content-type')).toContain('application/json')
      const body = await res.text()
      expect(res.headers.get('etag')).toBe(`"${await sha256Hex(body)}"`)
      expect(() => JSON.parse(body)).not.toThrow()
    })
    it(`${path}: If-None-Match with the ETag is a 304 with no body; another tag is a 200`, async () => {
      const etag = (await SELF.fetch(`${ORIGIN}${path}`)).headers.get('etag')!
      const same = await SELF.fetch(`${ORIGIN}${path}`, { headers: { 'if-none-match': etag } })
      expect(same.status).toBe(304)
      expect(await same.text()).toBe('')
      expect(same.headers.get('etag')).toBe(etag)
      expect(same.headers.get('cache-control')).toBe('public, max-age=300')
      const weak = await SELF.fetch(`${ORIGIN}${path}`, { headers: { 'if-none-match': `"other", W/${etag}` } })
      expect(weak.status).toBe(304)
      const other = await SELF.fetch(`${ORIGIN}${path}`, { headers: { 'if-none-match': '"0000"' } })
      expect(other.status).toBe(200)
    })
  }
  it('the JWKS and the agent document are not given the five-minute lifetime', async () => {
    const res = await SELF.fetch(`${ORIGIN}/.well-known/jwks.json`)
    expect(res.headers.get('cache-control')).toBeNull()
  })
})
