# encrypt

The send side of end-to-end encrypted agent messaging: give it the messaging service, the
recipient, and the text; it fetches the recipient's key from that service, encrypts, and delivers
the ciphertext there, acting for the person over an AAuth call chain. This is the code that runs
the hosted default at `encrypt.aauth.dev`, and it is what you deploy to run your own. The read side
is [decrypt](https://github.com/aauth-dev/decrypt) (`decrypt.aauth.dev`).

**Status: built 2026-09-14 (plan D26, Part C).** One operation, `sendMessage`; text only, 64 KB
(D25). Nothing in the code names a messaging service: `resource` is a parameter whose default is the
`DEFAULT_RESOURCE` var in `wrangler.jsonc` (`https://secret.agent.coop` for this host), and the tests
chain to a fake at a made-up host.

## What it is

- A Cloudflare Worker, an [AAuth](https://aauth.dev) resource with `access_mode: person-token`,
  and an AAuth agent toward the messaging service (`/.well-known/aauth-agent.json`,
  `aauth:send@<host>`). Stateless: no D1, no R2, no KV. In secret.agent.coop's terms it is a
  **send service** (plan D27): a person's account names theirs as `send_message_with`.
- `POST /send` (`sendMessage`) `{from, to, text, resource?, idempotency_key?}`:
  1. verifies the caller's person token (audience this service);
  2. asks the Person Server that issued it for a person token for `resource`, with the caller's
     token as `upstream_token` (call chaining; no consent card);
  3. `getPublicKey`: `GET {resource}/public-key?from=&to=` with that token, signed with `AGENT_KEY`;
  4. encrypts `{"text": …}` to that key as one compact JWE, ECDH-ES + A256GCM on P-256, per
     [spec/container.md](https://github.com/aauth-dev/decrypt/blob/main/spec/container.md),
     on Web Crypto directly (`src/jwe.ts`);
  5. `uploadMessage`: `POST {resource}/messages {from, to, jwe}`; on `409 key_rotated` it goes back
     to step 3, once;
  6. returns `{id, from, to, kid, size, resource}`.
- `from` is required: a person has several addresses. `resource` is optional.
- Refusals from the messaging service (`not_connected`, `recipient_has_no_key`, `rate_limited`)
  pass through with their status and `step: get_public_key | upload_message`. `text_too_long` (413)
  and `attachments_not_supported` (400) are this service's. `502` with `step: person_token` when the
  Person Server refuses the chain.
- It sees the plaintext of each message and the recipient's address, holds a token in the person's
  name for the messaging service for the length of the call, and stores nothing. Events carry a
  hash of the identity, the size, the key id, the messaging service, and the message id: never
  text or addresses. [Privacy](public/privacy.html).
- `openapi.json` and `/.well-known/aauth-resource.json` are served with
  `Cache-Control: public, max-age=300` and an `ETag`.

Two keys, both Ed25519 private JWKs: `SIGNING_KEY` signs the agent token (published at
`/.well-known/jwks.json`); `AGENT_KEY` signs the requests this service makes and is `cnf` in the
agent token and in the chained person token. `src/agent-identity.ts` and `test/fake-ps/` are copies
of secret-agent-coop's; a shared `@aauth/intermediary` package is a later increment.

## Use it from an agent

With the AAuth MCP: `connect_resources {items: [{resource: "encrypt.aauth.dev"}]}` (one card), then
`invoke {resource: "encrypt.aauth.dev", op_id: "sendMessage", body: {from: "mailto:you@example.com", to: "mailto:bob@example.com", text: "…"}}`.
Put the fields directly in `body`. The recipient reads with `listMessages` at the messaging service
and `readMessage {id}` at their read service (default decrypt.aauth.dev). The full flow is in the
[secret-agent-coop skill](https://github.com/aauth-dev/secret-agent-coop/tree/main/skills/secret-agent-coop).

## Run your own

```
npm install
npm run generate-key | npx wrangler secret put SIGNING_KEY
npm run generate-key | npx wrangler secret put AGENT_KEY
npx wrangler deploy                              # set your own route / custom domain in wrangler.jsonc
```

Then `connect_resources` your host from your agent and call `sendMessage` there. The messaging
service accepts a message from any encrypt and does not need to know which one delivered it.

## Develop

```
npm test          # vitest, Workers pool; fake Person Server and fake messaging service in test/fake-ps
npm run typecheck
bash scripts/smoke.sh [base_url]   # live: public surface, agent document, 401 shape
```

## License

MIT
