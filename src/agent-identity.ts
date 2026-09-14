// encrypt's own agent identity (D26). On every send, encrypt is an AAuth
// intermediary toward the messaging service the caller named: it presents
// an agent token to the Person Server (with the caller's person token as
// upstream_token) and signs the requests with AGENT_KEY.
//
// Copied from secret-agent-coop/service/src/agent-identity.ts with the sub
// changed; the later increment 7 (@aauth/intermediary) makes it one module.
//
// Two keys, on purpose:
//   SIGNING_KEY signs the agent token (and resource tokens). Its public half
//               is in /.well-known/jwks.json, which /.well-known/aauth-agent.json
//               names as jwks_uri, so a PS can verify the agent token.
//   AGENT_KEY   signs the HTTP requests. Its public half is cnf.jwk in the
//               agent token and, after the chain, in the person token the PS
//               issues to encrypt for the messaging service.
//
// Hellō verifies (Wallet svr/src/aauth/verify.js): iss, sub, cnf.jwk,
// dwk: 'aauth-agent.json', iat, exp; header typ 'aa-agent+jwt', alg
// 'Ed25519' (fully specified, never EdDSA), kid matching a key at the
// issuer's jwks_uri; sub is aauth:local@domain. The upstream token's aud must
// equal this token's iss, so iss is exactly ORIGIN.
import type { GetKeyMaterial } from '@aauth/agent'
import { getPublicJWK, importSigningKey, signJWT } from './crypto'
import type { Env } from './types'

const LIFETIME_S = 3600
const REFRESH_BEFORE_S = 300

interface Cached {
  jwt: string
  exp: number
}

let cached: Cached | undefined
let cachedFor: string | undefined

/** `aauth:send@<origin host>`: the one identity encrypt acts under. */
export function agentSub(origin: string): string {
  return `aauth:send@${new URL(origin).host}`
}

/** The public half of AGENT_KEY as it goes into cnf.jwk. */
export async function agentPublicJwk(env: Env): Promise<JsonWebKey> {
  const { kid: _kid, key_ops: _ops, ...jwk } = await getPublicJWK(env.AGENT_KEY)
  return jwk
}

/**
 * encrypt's agent token, minted on demand and cached per isolate until five
 * minutes before it expires. Signed with SIGNING_KEY; cnf is AGENT_KEY.
 */
export async function agentToken(env: Env): Promise<string> {
  const now = Math.floor(Date.now() / 1000)
  if (cached && cachedFor === env.ORIGIN && cached.exp - REFRESH_BEFORE_S > now) return cached.jwt
  const [privateKey, signingPub, cnf] = await Promise.all([
    importSigningKey(env.SIGNING_KEY),
    getPublicJWK(env.SIGNING_KEY),
    agentPublicJwk(env),
  ])
  const exp = now + LIFETIME_S
  const jwt = await signJWT(
    { alg: 'Ed25519', typ: 'aa-agent+jwt', kid: signingPub.kid },
    { iss: env.ORIGIN, dwk: 'aauth-agent.json', sub: agentSub(env.ORIGIN), cnf: { jwk: cnf }, iat: now, exp },
    privateKey,
  )
  cached = { jwt, exp }
  cachedFor = env.ORIGIN
  return jwt
}

/** Key material for createSignedFetch toward a PS: AGENT_KEY signs, the agent token is the Signature-Key. */
export function agentKeyMaterial(env: Env): GetKeyMaterial {
  return async () => ({
    signingKey: JSON.parse(env.AGENT_KEY) as JsonWebKey,
    signatureKey: { type: 'jwt', jwt: await agentToken(env) },
  })
}

/** Key material for createSignedFetch toward a resource: AGENT_KEY signs, a person token is the Signature-Key. */
export function personKeyMaterial(env: Env, personToken: string): GetKeyMaterial {
  return async () => ({
    signingKey: JSON.parse(env.AGENT_KEY) as JsonWebKey,
    signatureKey: { type: 'jwt', jwt: personToken },
  })
}

/** /.well-known/aauth-agent.json: what a PS reads to verify the agent token. */
export function agentDocument(origin: string): { issuer: string; name: string; jwks_uri: string } {
  return { issuer: origin, name: new URL(origin).host, jwks_uri: `${origin}/.well-known/jwks.json` }
}

/** Tests only: forget the cached token. */
export function resetAgentTokenCache(): void {
  cached = undefined
  cachedFor = undefined
}
