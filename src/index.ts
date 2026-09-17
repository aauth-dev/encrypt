// The send service Worker (plan D26 Part C, D27 section 6). Public:
// well-known (resource and agent), JWKS, OpenAPI, pages. Protected (person
// token): sendMessage. Stateless.
import { Hono } from 'hono'
import { cors } from 'hono/cors'
import { agentDocument } from './agent-identity'
import { requireIdentity } from './auth'
import { getPublicJWK } from './crypto'
import { emit } from './events'
import { openapi } from './openapi'
import { sendMessage } from './send'
import type { HonoEnv } from './types'

const app = new Hono<HonoEnv>()

app.onError((err, c) => {
  const error = err instanceof Error ? err : new Error(String(err))
  console.error('unhandled_error', error.stack ?? String(error))
  emit(c, { event: 'unhandled_error', level: 50, msg: error.message, error_name: error.name, error_stack: error.stack })
  return c.json({ error: 'internal_error' }, 500)
})

app.use('*', cors({ origin: '*', exposeHeaders: ['AAuth-Requirement', 'Signature-Error', 'Accept-Signature', 'Accept-Signature-Scheme', 'Accept-Signature-Alg'] }))

app.get('/.well-known/aauth-resource.json', (c) => {
  const origin = c.env.ORIGIN
  return c.json({
    issuer: origin,
    jwks_uri: `${origin}/.well-known/jwks.json`,
    name: new URL(origin).host,
    description: 'A send service: encrypts a message to a connected person\'s key and uploads it to your messaging service for you. It sees the plaintext of what it sends and stores nothing. The messaging service is a parameter with a default; the code is open and you can run your own.',
    access_mode: 'person-token',
    r3_vocabularies: { 'urn:aauth:vocabulary:openapi': `${origin}/openapi.json` },
    contact: { feedback: 'feedback@agent.coop', abuse: 'abuse@agent.coop' },
    llms_txt: `${origin}/llms.txt`,
  })
})
// encrypt is an agent toward the messaging service (D26). A PS verifies the
// agent token against jwks_uri.
app.get('/.well-known/aauth-agent.json', (c) => c.json(agentDocument(c.env.ORIGIN)))
app.get('/.well-known/jwks.json', async (c) => c.json({ keys: [await getPublicJWK(c.env.SIGNING_KEY)] }))
app.get('/openapi.json', (c) => c.json(openapi(c.env)))
app.get('/health', (c) => c.json({ status: 'ok', service: c.env.SERVICE }))

app.post('/send', requireIdentity, sendMessage)

export default { fetch: app.fetch }
