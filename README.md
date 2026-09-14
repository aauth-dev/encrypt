# encrypt

The send side of end-to-end encrypted agent messaging: give it the messaging service, the
recipient, and the text; it fetches the recipient's key from that service, encrypts, and delivers
the ciphertext there, acting for the person over an AAuth call chain. This is the code that runs
the hosted default at `encrypt.aauth.dev`, and it is what you deploy to run your own. The read side
is [decrypt-agent-coop](https://github.com/aauth-dev/decrypt-agent-coop) (`decrypt.aauth.dev`).

**Status: built 2026-09-14 (plan D26, Part C).** One operation, `sendMessage`; text only, 64 KB
(D25). Nothing in the code names a messaging service: `resource` is a required parameter, and the
tests chain to a fake at a made-up host. The default for agent.coop is `https://secret.agent.coop`,
named only in `public/llms.txt`.

## What it is

- A Cloudflare Worker, an [AAuth](https://aauth.dev) resource with `access_mode: person-token`,
  and an AAuth agent toward the messaging service (`/.well-known/aauth-agent.json`). Stateless: no
  D1, no R2, no KV.
- `POST /send` (`sendMessage`) `{resource, to, text, from?, idempotency_key?}`:
  1. verifies the caller's person token (audience this service);
  2. asks the Person Server that issued it for a person token for `resource`, with the caller's
     token as `upstream_token` (call chaining; no consent card);
  3. `GET {resource}/keys?address={to}` with that token, signed with `AGENT_KEY`;
  4. encrypts `{text}` to the first key: JWE ECDH-ES + A256GCM on P-256, split per
     [spec/container.md](https://github.com/aauth-dev/decrypt-agent-coop/blob/main/spec/container.md),
     on Web Crypto directly (`src/jwe.ts`);
  5. `POST {resource}/messages` then `PUT {resource}/messages/{id}/blob` as `application/octet-stream`;
  6. returns `{id, to, from, kid, size, resource}`.
- Refusals from the messaging service (`not_connected`, `recipient_has_no_key`, `rate_limited`)
  pass through with their status and a `step`. `text_too_long` (413) and
  `attachments_not_supported` (400) are this service's.
- It sees the plaintext of each message and the recipient's address, holds a token in the person's
  name for the messaging service for the length of the call, and stores nothing. Events carry a
  hash of the identity, the size, the key id, the messaging service, and the message id: never
  text or addresses. [Privacy](public/privacy.html).

Two keys, both Ed25519 private JWKs: `SIGNING_KEY` signs the agent token (published at
`/.well-known/jwks.json`); `AGENT_KEY` signs the requests this service makes and is `cnf` in the
agent token and in the chained person token. `src/agent-identity.ts` and `test/fake-ps/` are copies
of secret-agent-coop's; a shared `@aauth/intermediary` package is a later increment.

## Use it from an agent

With the AAuth MCP: `connect_resources [{resource: "encrypt.aauth.dev"}]` (one card), then
`invoke sendMessage {resource: "https://secret.agent.coop", to: "mailto:bob@example.com", text: "…"}`.
The recipient reads with `getMessages` and `getMessage` at the messaging service and
`decryptEnvelope` at decrypt.aauth.dev. The full flow is in the
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

Until `@aauth/agent` 4.1.0 (the `upstreamToken` option) is published, `node_modules/@aauth/agent`
is an `npm link` to `packages-js/agent` and `package-lock.json` does not list it.

## License

MIT
