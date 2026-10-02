// Token revocation (AAuth Protocol -11 §Token Revocation): the person server
// (or access server) that issued a token this service verifies withdraws it
// before its exp. Same shape as senzing.aauth.dev's /aauth/revoke.
//
// The caller signs as itself (`Signature-Key: sig=jwks_uri`, its issuer as
// `id`, its metadata document as `dwk`), and that is how the token's issuer
// is established: the verified signer, never a body parameter, so a caller
// can only retire its own tokens. The body names the token: `jti` and `exp`.
// The signature MUST cover content-type and content-digest: the body is what
// says which token dies. The signature step is here; the caller allow-list,
// the body checks, the (iss, jti) row and the 200 / 400 / 403 answers are
// @aauth/resource's applyRevocation.
//
// The list is KV (REVOCATION): `revoked:{iss}:{jti}` rows with a TTL of the
// token's remaining life, plaintext markers, read by every isolate. A
// revoked token presented afterwards is refused by requireIdentity (auth.ts)
// with 401 + `Signature-Error: error=revoked_jwt`.
import type { Context } from 'hono'
import {
  verify as httpSigVerify,
  generateSignatureErrorHeader,
  generateAcceptSignatureHeader,
  generateAcceptSignatureSchemeHeader,
  generateAcceptSignatureAlgHeader,
  parseDictionary,
  isInnerList,
} from '@hellocoop/httpsig'
import { KVRevocationStore, applyRevocation, revocationResponse, type RevocationStore } from '@aauth/resource'
import { emit, emitVerifyFailed } from './events'
import type { Env, HonoEnv } from './types'

/** The servers whose revocations are honoured when REVOCATION_ISSUERS is unset: the Hellō person servers and access.aauth.dev. */
export const DEFAULT_REVOCATION_ISSUERS = ['https://person.hello.coop', 'https://person.hello-beta.net', 'https://access.aauth.dev']

const REQUIRED_COMPONENTS = ['@method', '@authority', '@path', 'signature-key', 'content-type', 'content-digest']

const MAX_BODY = 4096 // {jti, exp}

export function revocationStore(env: Pick<Env, 'REVOCATION'>): RevocationStore {
  return new KVRevocationStore(env.REVOCATION)
}

/** REVOCATION_ISSUERS, comma-separated; unset is the default list. */
export function revocationIssuers(env: Pick<Env, 'REVOCATION_ISSUERS'>): string[] {
  if (env.REVOCATION_ISSUERS === undefined) return DEFAULT_REVOCATION_ISSUERS
  return env.REVOCATION_ISSUERS.split(',')
    .map((s) => s.trim().replace(/\/$/, ''))
    .filter(Boolean)
}

function coveredComponents(signatureInput: string | undefined, label: string): string[] {
  if (!signatureInput) return []
  try {
    const member = parseDictionary(signatureInput).get(label)
    return member && isInnerList(member) ? member[0].map(([item]) => String(item)) : []
  } catch {
    return []
  }
}

export async function handleRevoke(c: Context<HonoEnv>): Promise<Response> {
  const url = new URL(c.req.url)
  const body = new Uint8Array(await c.req.raw.arrayBuffer())
  if (body.byteLength > MAX_BODY) return c.json({ error: 'payload_too_large' }, 413)

  if (!c.req.header('signature') && !c.req.header('signature-input')) {
    emitVerifyFailed(c, 'no_signature')
    return c.json(
      { error: 'signature_required', detail: 'the revocation endpoint requires a signed request from the server that issued the token' },
      401,
      {
        'Accept-Signature': generateAcceptSignatureHeader({ label: 'sig', components: REQUIRED_COMPONENTS }),
        'Accept-Signature-Scheme': generateAcceptSignatureSchemeHeader(['jwks_uri']),
      },
    )
  }
  const sig = await httpSigVerify(
    { method: c.req.method, authority: url.host, path: url.pathname, headers: c.req.raw.headers, body },
    { requireContentDigest: true },
  )
  if (!sig.verified) {
    const headers: Record<string, string> = {}
    if (sig.signatureError) headers['Signature-Error'] = generateSignatureErrorHeader(sig.signatureError)
    if (sig.acceptSignatureAlg) headers['Accept-Signature-Alg'] = generateAcceptSignatureAlgHeader(sig.acceptSignatureAlg)
    emitVerifyFailed(c, 'signature_invalid', { detail: sig.error, signature_error_code: sig.signatureError?.error })
    return c.json({ error: 'signature_verification_failed', detail: sig.error }, 401, headers)
  }
  // An agent presenting a token is not a server signing as itself.
  if (sig.keyType !== 'jwks_uri' || !sig.jwks_uri) {
    emitVerifyFailed(c, 'wrong_key_scheme', { actual_key_type: sig.keyType })
    return c.json({ error: 'invalid_signature', detail: 'the revocation endpoint requires Signature-Key with the jwks_uri scheme' }, 401, {
      'Signature-Error': generateSignatureErrorHeader({ error: 'unsupported_scheme' }),
      'Accept-Signature-Scheme': generateAcceptSignatureSchemeHeader(['jwks_uri']),
    })
  }
  const covered = coveredComponents(c.req.header('signature-input'), sig.label)
  const missing = REQUIRED_COMPONENTS.filter((component) => !covered.includes(component))
  if (missing.length) {
    emitVerifyFailed(c, 'components_missing', { missing })
    return c.json({ error: 'invalid_signature', detail: `signature must cover ${missing.join(', ')}` }, 401, {
      'Signature-Error': generateSignatureErrorHeader({ error: 'invalid_input', required_input: REQUIRED_COMPONENTS }),
    })
  }

  const caller = { id: sig.jwks_uri.id, dwk: sig.jwks_uri.dwk }
  const outcome = await applyRevocation(caller, new TextDecoder().decode(body), { store: revocationStore(c.env), issuers: revocationIssuers(c.env) })
  emit(
    c,
    outcome.ok
      ? { event: 'token_revoked', iss: outcome.iss, jti: outcome.jti, exp: outcome.exp, already_expired: outcome.expired }
      : { event: 'revocation_refused', level: 40, caller: caller.id, caller_dwk: caller.dwk, status: outcome.status, error: outcome.error, detail: outcome.detail },
  )
  return revocationResponse(outcome)
}
