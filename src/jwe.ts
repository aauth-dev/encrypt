// JWE ECDH-ES + A256GCM on P-256, produced disassembled (decrypt-agent-coop
// spec/container.md; plan D18, D19), on Web Crypto directly: ephemeral
// P-256 → ECDH → Concat KDF (RFC 7518 §4.6.2) → AES-256-GCM with the
// base64url protected header as AAD. A port of the reference encoder,
// secret-agent-coop/skills/secret-agent-coop/scripts/encrypt.mjs.
import { b64urlEncode } from './util'

export interface Envelope {
  /** base64url protected header, verbatim (it is the AAD) */
  protected: string
  iv: string
  tag: string
  ciphertext: Uint8Array
  kid: string
}

export class JweError extends Error {
  constructor(readonly code: string, message: string) {
    super(message)
  }
}

function lenPrefixed(bytes: Uint8Array): Uint8Array {
  const out = new Uint8Array(4 + bytes.length)
  new DataView(out.buffer).setUint32(0, bytes.length)
  out.set(bytes, 4)
  return out
}

function concat(...parts: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0))
  let o = 0
  for (const p of parts) {
    out.set(p, o)
    o += p.length
  }
  return out
}

/** Concat KDF, one round (keydatalen 256 fits one SHA-256 block of output). No apu/apv. */
async function concatKdf(z: Uint8Array): Promise<Uint8Array> {
  const enc = new TextEncoder()
  const otherInfo = concat(
    lenPrefixed(enc.encode('A256GCM')),
    lenPrefixed(new Uint8Array(0)),
    lenPrefixed(new Uint8Array(0)),
    new Uint8Array([0, 0, 1, 0]), // keydatalen = 256 bits
  )
  const round = concat(new Uint8Array([0, 0, 0, 1]), z, otherInfo)
  return new Uint8Array(await crypto.subtle.digest('SHA-256', round as BufferSource))
}

/** A public EC P-256 JWK, or null. Mirrors secret's validatePublicJwk. */
export function publicP256(jwk: unknown): JsonWebKey | null {
  if (!jwk || typeof jwk !== 'object' || Array.isArray(jwk)) return null
  const k = jwk as Record<string, unknown>
  if (k.kty !== 'EC' || k.crv !== 'P-256' || typeof k.x !== 'string' || typeof k.y !== 'string') return null
  if (k.x.length !== 43 || k.y.length !== 43 || 'd' in k) return null
  return { kty: 'EC', crv: 'P-256', x: k.x, y: k.y }
}

/** Encrypt `plaintext` to the recipient's key. `kid` goes into the protected header verbatim. */
export async function encryptTo(recipientJwk: JsonWebKey, kid: string, plaintext: Uint8Array): Promise<Envelope> {
  const pub = publicP256(recipientJwk)
  if (!pub) throw new JweError('invalid_recipient_key', 'recipient key must be a public EC P-256 JWK')
  let recipient: CryptoKey
  try {
    recipient = await crypto.subtle.importKey('jwk', pub, { name: 'ECDH', namedCurve: 'P-256' }, false, [])
  } catch {
    throw new JweError('invalid_recipient_key', 'recipient key did not import as a P-256 public key')
  }
  const eph = (await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits'])) as CryptoKeyPair
  const ephJwk = (await crypto.subtle.exportKey('jwk', eph.publicKey)) as JsonWebKey
  const header = { alg: 'ECDH-ES', enc: 'A256GCM', kid, epk: { kty: 'EC', crv: 'P-256', x: ephJwk.x, y: ephJwk.y } }
  const protectedB64 = b64urlEncode(new TextEncoder().encode(JSON.stringify(header)))

  const z = new Uint8Array(await crypto.subtle.deriveBits({ name: 'ECDH', public: recipient } as never, eph.privateKey, 256))
  const cek = await crypto.subtle.importKey('raw', await concatKdf(z), { name: 'AES-GCM' }, false, ['encrypt'])
  const iv = crypto.getRandomValues(new Uint8Array(12))
  const out = new Uint8Array(
    await crypto.subtle.encrypt({ name: 'AES-GCM', iv, additionalData: new TextEncoder().encode(protectedB64), tagLength: 128 }, cek, plaintext as BufferSource),
  )
  return {
    protected: protectedB64,
    iv: b64urlEncode(iv),
    tag: b64urlEncode(out.slice(out.length - 16)),
    ciphertext: out.slice(0, out.length - 16),
    kid,
  }
}
