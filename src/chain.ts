// The call chain from sendMessage to the messaging service (D26, Part C).
// The caller presented a person token for encrypt; encrypt asks the PS that
// issued it for a person token for `resource` with that token as
// upstream_token (no consent card), then talks to `resource` with the
// chained token, signing with AGENT_KEY. A 202 from the PS would mean it
// wants a card; that is an error for this cut. Tokens are never logged.
import { createSignedFetch, requestPersonToken, PersonTokenError } from '@aauth/agent'
import type { FetchLike, PersonServerMetadata } from '@aauth/agent'
import { agentKeyMaterial, personKeyMaterial } from './agent-identity'
import { b64urlDecode } from './util'
import type { Env } from './types'

export interface ChainFailure {
  error: string
  detail: string
}

class InteractionRequired extends Error {
  constructor() {
    super('the Person Server asked for an interaction; chained requests must not')
    this.name = 'InteractionRequired'
  }
}

const metadataCache = new Map<string, PersonServerMetadata>()

function issuerOf(jwt: string): string | null {
  try {
    const payload = JSON.parse(new TextDecoder().decode(b64urlDecode(jwt.split('.')[1] ?? ''))) as Record<string, unknown>
    return typeof payload.iss === 'string' ? payload.iss : null
  } catch {
    return null
  }
}

/**
 * A signed fetch toward `resource`, carrying a person token for it obtained
 * over the chain. Returns the failure instead of throwing when the PS
 * refuses; the route reports it.
 */
export async function chainedFetch(env: Env, upstreamToken: string, resource: string): Promise<{ ok: true; fetch: FetchLike } | ({ ok: false } & ChainFailure)> {
  const ps = issuerOf(upstreamToken)
  if (!ps) return { ok: false, error: 'invalid_upstream_token', detail: 'the presented token has no iss' }
  const psFetch = createSignedFetch(agentKeyMaterial(env), { signBody: true })
  const guarded: FetchLike = async (url, init) => {
    const res = await psFetch(url, init)
    if (res.status === 202) throw new InteractionRequired()
    return res
  }
  try {
    const { personToken } = await requestPersonToken({
      signedFetch: guarded,
      personServerUrl: ps,
      personServerMetadata: metadataCache.get(ps),
      onMetadata: (m) => metadataCache.set(ps, m),
      resource,
      upstreamToken,
    })
    return { ok: true, fetch: createSignedFetch(personKeyMaterial(env, personToken)) }
  } catch (err) {
    metadataCache.delete(ps)
    if (err instanceof PersonTokenError) return { ok: false, error: err.error ?? `http_${err.status}`, detail: err.detail ?? err.message }
    if (err instanceof InteractionRequired) return { ok: false, error: 'interaction_required', detail: err.message }
    return { ok: false, error: 'person_token_failed', detail: err instanceof Error ? err.message : String(err) }
  }
}

/** The error body of a refusal from the resource, for pass-through. */
export async function passThrough(res: Response): Promise<Record<string, unknown>> {
  const text = await res.text()
  try {
    const body = JSON.parse(text) as unknown
    if (body && typeof body === 'object' && !Array.isArray(body)) return body as Record<string, unknown>
  } catch {
    /* not JSON */
  }
  return { error: `http_${res.status}`, detail: text.slice(0, 300) }
}
