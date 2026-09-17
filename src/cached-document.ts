// The documents agents and the AAuth proxy cache (plan read-send-services
// section 12c): openapi.json and /.well-known/aauth-resource.json go out
// with Cache-Control: public, max-age=300 and a strong ETag, the SHA-256 of
// the body. Five minutes lets a changed operation reach agents soon after a
// deploy; the ETag keeps the refetch to a 304 when nothing changed.
import type { Context } from 'hono'

export const DOCUMENT_CACHE_CONTROL = 'public, max-age=300'

async function sha256Hex(text: string): Promise<string> {
  const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(text)))
  return [...digest].map((b) => b.toString(16).padStart(2, '0')).join('')
}

export async function cachedDocument(c: Context, document: unknown): Promise<Response> {
  const body = JSON.stringify(document)
  const etag = `"${await sha256Hex(body)}"`
  const headers = { 'cache-control': DOCUMENT_CACHE_CONTROL, etag }
  const ifNoneMatch = c.req.header('if-none-match')
  if (ifNoneMatch) {
    const tags = ifNoneMatch.split(',').map((t) => t.trim().replace(/^W\//, ''))
    if (tags.includes('*') || tags.includes(etag)) return new Response(null, { status: 304, headers })
  }
  return new Response(body, { status: 200, headers: { ...headers, 'content-type': 'application/json' } })
}
