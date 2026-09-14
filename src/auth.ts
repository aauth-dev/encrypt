// AAuth verification: RFC 9421 signature, then the person (or PS-issued
// auth) token, then the identity (iss, sub). No step-up here: encrypt is
// person-token mode. The presented token is kept on the identity: it is the
// upstream_token when this service chains to the messaging service.
// Copied from decrypt-agent-coop/src/auth.ts.
import type { Context, MiddlewareHandler } from 'hono'
import {
  verify as httpSigVerify,
  generateSignatureErrorHeader,
  generateAcceptSignatureHeader,
  generateAcceptSignatureSchemeHeader,
  generateAcceptSignatureAlgHeader,
} from '@hellocoop/httpsig'
import { AAuthTokenError, TOKEN_TYP, buildAAuthHeader, verifyToken, type VerifiedAuthToken, type VerifiedPersonToken } from '@aauth/resource'
import { emitVerifyFailed } from './events'
import type { HonoEnv } from './types'

// {resource, to, text ≤ 64 KB, from?, idempotency_key?} as JSON: 64 KB of text is at most 4× that as escaped JSON.
const MAX_BODY = 300_000

const personTokenHeaders = () => ({
  'AAuth-Requirement': buildAAuthHeader('person-token'),
  'Accept-Signature': generateAcceptSignatureHeader({ label: 'sig', components: ['@method', '@authority', '@path', 'signature-key'] }),
  'Accept-Signature-Scheme': generateAcceptSignatureSchemeHeader(['jwt']),
})

async function readBody(c: Context<HonoEnv>): Promise<Uint8Array | undefined | 'too_large'> {
  const req = c.req.raw
  if (req.method === 'GET' || req.method === 'HEAD' || !req.body) return undefined
  if (Number(req.headers.get('content-length') ?? '0') > MAX_BODY) return 'too_large'
  const buf = new Uint8Array(await req.arrayBuffer())
  return buf.byteLength > MAX_BODY ? 'too_large' : buf
}

export const requireIdentity: MiddlewareHandler<HonoEnv> = async (c, next) => {
  const url = new URL(c.req.url)
  const body = await readBody(c)
  if (body === 'too_large') return c.json({ error: 'payload_too_large' }, 413)
  c.set('rawBody', body)

  const sig = await httpSigVerify({
    method: c.req.method,
    authority: url.host,
    path: url.pathname,
    query: url.search ? url.search.slice(1) : undefined,
    headers: c.req.raw.headers,
    ...(body ? { body } : {}),
  })
  if (!sig.verified) {
    const noSig = !c.req.header('signature') && !c.req.header('signature-input')
    if (noSig) {
      emitVerifyFailed(c, 'no_signature')
      return c.json({ error: 'person_token_required' }, 401, personTokenHeaders())
    }
    const headers: Record<string, string> = { 'AAuth-Requirement': buildAAuthHeader('person-token') }
    if (sig.signatureError) headers['Signature-Error'] = generateSignatureErrorHeader(sig.signatureError)
    if (sig.acceptSignatureAlg) headers['Accept-Signature-Alg'] = generateAcceptSignatureAlgHeader(sig.acceptSignatureAlg)
    emitVerifyFailed(c, 'signature_invalid', { detail: sig.error, signature_error_code: sig.signatureError?.error })
    return c.json({ error: 'signature_verification_failed', detail: sig.error }, 401, headers)
  }
  if (sig.keyType !== 'jwt' || !sig.jwt) {
    emitVerifyFailed(c, 'wrong_key_scheme', { actual_key_type: sig.keyType })
    return c.json({ error: 'Signature-Key must use sig=jwt scheme' }, 401, {
      'AAuth-Requirement': buildAAuthHeader('person-token'),
      'Accept-Signature-Scheme': generateAcceptSignatureSchemeHeader(['jwt']),
    })
  }
  const typ = (sig.jwt.header as Record<string, unknown>).typ
  const accept: Array<'person' | 'auth'> = typ === TOKEN_TYP.person ? ['person'] : typ === TOKEN_TYP.auth ? ['auth'] : []
  if (accept.length === 0) {
    emitVerifyFailed(c, 'unsupported_jwt_type', { jwt_typ: typ })
    return c.json({ error: 'person_token_required', detail: `cannot serve a ${String(typ)} here` }, 401, { 'AAuth-Requirement': buildAAuthHeader('person-token') })
  }
  try {
    const verified = await verifyToken({ jwt: sig.jwt.raw, httpSignatureThumbprint: sig.thumbprint, resource: c.env.ORIGIN, accept })
    if (verified.type === 'person') {
      const v = verified as VerifiedPersonToken
      c.set('identity', { iss: v.iss, sub: v.sub, kind: 'person', jwt: sig.jwt.raw, thumbprint: sig.thumbprint })
    } else {
      const v = verified as VerifiedAuthToken
      c.set('identity', { iss: v.ps, sub: v.sub, kind: 'auth', jwt: sig.jwt.raw, thumbprint: sig.thumbprint })
    }
  } catch (err) {
    if (err instanceof AAuthTokenError) {
      emitVerifyFailed(c, err.code, { detail: err.message })
      return c.json({ error: err.code, detail: err.message }, 401, { 'AAuth-Requirement': buildAAuthHeader('person-token') })
    }
    throw err
  }
  await next()
}

export function parseJsonBody<T = Record<string, unknown>>(c: Context<HonoEnv>): T | null {
  const raw = c.get('rawBody')
  if (!raw || raw.byteLength === 0) return {} as T
  try {
    const v = JSON.parse(new TextDecoder().decode(raw))
    return v && typeof v === 'object' && !Array.isArray(v) ? (v as T) : null
  } catch {
    return null
  }
}
