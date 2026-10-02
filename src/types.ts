export interface Env {
  SERVICE: string
  ORIGIN: string
  DEFAULT_RESOURCE: string // the messaging service sendMessage delivers to when the caller names none (Q7)
  SIGNING_KEY: string // Ed25519 private JWK (JSON), secret: signs the agent token
  AGENT_KEY: string // Ed25519 private JWK (JSON), secret: signs requests made as an intermediary
  REVOCATION: KVNamespace // the revocation list (revocation.ts)
  REVOCATION_ISSUERS?: string // comma-separated servers whose revocations are honoured; unset = revocation.ts DEFAULT_REVOCATION_ISSUERS
  ASSETS?: Fetcher
  EVENTS_QUEUE?: Queue
}

/** The verified caller: (iss, sub) from a person token, plus the token itself for the chain. */
export interface Identity {
  iss: string
  sub: string
  kind: 'person' | 'auth'
  /** the presented token, verbatim: it is the upstream_token of the chain */
  jwt: string
  thumbprint: string
}

export type HonoEnv = { Bindings: Env; Variables: { identity: Identity; rawBody: Uint8Array | undefined } }
