export function b64urlEncode(bytes: Uint8Array): string {
  let s = ''
  for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i])
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

export function b64urlDecode(str: string): Uint8Array {
  const padded = str + '='.repeat((4 - (str.length % 4)) % 4)
  const bin = atob(padded.replace(/-/g, '+').replace(/_/g, '/'))
  const out = new Uint8Array(bin.length)
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i)
  return out
}

export const B64URL_RE = /^[A-Za-z0-9_-]+$/
export const nowIso = () => new Date().toISOString()

export async function sha256(data: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.digest('SHA-256', data as BufferSource))
}

/** RFC 7638 thumbprint of an EC public JWK, base64url. */
export async function ecThumbprint(jwk: JsonWebKey): Promise<string> {
  const canonical = JSON.stringify({ crv: jwk.crv, kty: jwk.kty, x: jwk.x, y: jwk.y })
  return b64urlEncode(await sha256(new TextEncoder().encode(canonical)))
}

/** Identity on events: a hash of (iss, sub), never the pair itself (A8). */
export async function identityHash(iss: string, sub: string): Promise<string> {
  return b64urlEncode(await sha256(new TextEncoder().encode(`${iss}|${sub}`))).slice(0, 22)
}
