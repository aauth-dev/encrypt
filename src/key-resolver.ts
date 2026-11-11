// Key discovery. Every key this service looks up goes through one
// @hellocoop/httpsig key resolver on one store: the person server or access
// server behind a person or auth token (its iss and dwk, via @aauth/resource
// verifyToken), and a server that signs a revocation through the jwks_uri
// scheme (httpsig verify). The resolver holds the policy of
// draft-hardt-httpbis-signature-key §Caching and Performance: a 5 s fetch
// timeout, redirects refused, a one-minute refetch floor that also holds
// after a failed fetch, one refresh on an unknown kid, Cache-Control max-age
// honored down to the floor. The store is per isolate and bounded: its keys
// are URLs taken from requests that have not been verified yet.
import type { Context } from 'hono'
import { BoundedTtlCache, createKeyResolver, type KeyFetchEvent, type KeyResolver, type KeyStoreEntry } from '@hellocoop/httpsig'
import { emit } from './events'
import type { HonoEnv } from './types'

const keyStore = new BoundedTtlCache<KeyStoreEntry>(500)

/** Tests only: forget every fetched document, and with it the refetch floor. */
export function clearKeyCache(): void {
  keyStore.clear()
}

/**
 * The key resolver for one request. Every metadata and JWKS fetch it makes is
 * emitted as `aauth.encrypt.key_fetch` with the reason for the fetch and the
 * request it was made for. Resolvers share the store, so the cache and the
 * refetch floor hold across requests.
 */
export function keyResolverFor(c: Context<HonoEnv>): KeyResolver {
  return createKeyResolver({
    store: keyStore,
    onFetch: (event: KeyFetchEvent) =>
      emit(c, {
        event: 'aauth.encrypt.key_fetch',
        level: event.ok ? 30 : 40,
        msg: `${event.doc} fetch ${event.ok ? 'ok' : 'failed'} (${event.reason}): ${event.url}`,
        ...event,
      }),
  })
}
