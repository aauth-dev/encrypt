export interface Env {
  SERVICE: string
  ORIGIN: string
  SIGNING_KEY: string // Ed25519 private JWK (JSON), secret: signs the agent token
  AGENT_KEY: string // Ed25519 private JWK (JSON), secret: signs requests made as an intermediary
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
