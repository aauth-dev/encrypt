// Ed25519 JWT signing for resource tokens. Same shape as the other AAuth
// Workers (registry, notes, test-resource).
import { calculateThumbprint } from '@hellocoop/httpsig'
import { b64urlEncode } from './util'

const enc = new TextEncoder()

export async function importSigningKey(jwkJson: string): Promise<CryptoKey> {
  // workerd rejects alg "Ed25519" on OKP import; the algorithm is explicit.
  const { alg: _alg, ...jwk } = JSON.parse(jwkJson)
  return crypto.subtle.importKey('jwk', jwk, { name: 'Ed25519' }, false, ['sign'])
}

export async function getPublicJWK(jwkJson: string): Promise<JsonWebKey & { kid: string }> {
  const jwk = JSON.parse(jwkJson)
  const { d: _d, key_ops: _ops, ext: _ext, ...rest } = jwk
  const publicJwk = { ...rest, key_ops: ['verify'], alg: rest.alg ?? 'Ed25519' }
  const kid = await calculateThumbprint(publicJwk)
  return { ...publicJwk, kid }
}

export async function signJWT(
  header: Record<string, unknown>,
  payload: Record<string, unknown>,
  privateKey: CryptoKey,
): Promise<string> {
  const h = b64urlEncode(enc.encode(JSON.stringify(header)))
  const p = b64urlEncode(enc.encode(JSON.stringify(payload)))
  const sig = await crypto.subtle.sign('Ed25519', privateKey, enc.encode(`${h}.${p}`))
  return `${h}.${p}.${b64urlEncode(new Uint8Array(sig))}`
}
