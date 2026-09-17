// OpenAPI 3.1 for the send service, served at /openapi.json. One operation.
// Host names come from env (ORIGIN, DEFAULT_RESOURCE).
import type { Env } from './types'

export function openapi(env: Pick<Env, 'ORIGIN' | 'DEFAULT_RESOURCE'>) {
  return {
    openapi: '3.1.0',
    info: {
      title: new URL(env.ORIGIN).host,
      version: '0.2.0',
      description:
        `Sends an end-to-end encrypted message for you: give it your address, the recipient, and the text; it fetches the recipient's latest key from the messaging service, encrypts (compact JWE, ECDH-ES A256GCM, P-256), and uploads the JWE there, acting on your behalf over an AAuth call chain. It sees the plaintext of what it sends and stores nothing. The messaging service is \`resource\`, default ${env.DEFAULT_RESOURCE}.`,
    },
    servers: [{ url: env.ORIGIN }],
    paths: {
      '/send': {
        post: {
          operationId: 'sendMessage',
          summary: `Send a text message to a connected person. One call: fetches their key at the messaging service, encrypts, uploads. \`from\` is required: one of your addresses there. \`resource\` is the messaging service, default ${env.DEFAULT_RESOURCE}. Refusals from it (not_connected, recipient_has_no_key, rate_limited) pass through with \`step\`. Text only, up to 64 KB.`,
          requestBody: {
            required: true,
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  required: ['from', 'to', 'text'],
                  properties: {
                    from: { type: 'string', format: 'uri', description: 'Required. One of your addresses at the messaging service, in any spelling.', example: 'mailto:you@example.com' },
                    to: { type: 'string', format: 'uri', description: 'The recipient\'s address: peer_address on your connection.', example: 'mailto:bob@example.com' },
                    text: { type: 'string', description: 'The message. Up to 64 KB as JSON.' },
                    resource: { type: 'string', format: 'uri', description: `The messaging service to deliver through, as an https origin. Default ${env.DEFAULT_RESOURCE}.` },
                    idempotency_key: { type: 'string', maxLength: 64, description: 'Passed to the messaging service; a repeat with the same key returns the first message with replayed: true.' },
                  },
                },
              },
            },
          },
          responses: {
            '200': { description: 'Delivered', content: { 'application/json': { schema: { type: 'object', properties: { id: { type: 'string' }, from: { type: 'string' }, to: { type: 'string' }, kid: { type: 'string' }, size: { type: 'integer' }, resource: { type: 'string' }, replayed: { type: 'boolean' } } } } } },
            '400': { description: 'invalid_request (from, to, text, resource, idempotency_key) or attachments_not_supported; or a refusal from the messaging service with step' },
            '404': { description: 'not_connected, from the messaging service (step get_public_key)' },
            '409': { description: 'recipient_has_no_key (step get_public_key); key_rotated twice in a row (step upload_message)' },
            '413': { description: 'text_too_long: over 64 KB' },
            '429': { description: 'rate_limited, from the messaging service (step upload_message)' },
            '502': { description: 'step person_token: the Person Server refused a person token for resource (error is its code); or the resource did not answer' },
          },
        },
      },
    },
  }
}
