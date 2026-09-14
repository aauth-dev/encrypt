// OpenAPI 3.1 for encrypt.aauth.dev, served at /openapi.json. One operation.
export function openapi(origin: string) {
  return {
    openapi: '3.1.0',
    info: {
      title: 'encrypt.aauth.dev',
      version: '0.1.0',
      description:
        'Sends an end-to-end encrypted message for you: give it the messaging service, the recipient, and the text; it fetches the recipient\'s key from that service, encrypts (JWE ECDH-ES A256GCM, P-256), and delivers the ciphertext there, acting on your behalf over an AAuth call chain. It sees the plaintext of what it sends and stores nothing. The messaging service is a parameter (`resource`); llms.txt names the default.',
    },
    servers: [{ url: origin }],
    paths: {
      '/send': {
        post: {
          operationId: 'sendMessage',
          summary: 'Send a text message to a connected person through the messaging service named in `resource`. One call: fetches their key there, encrypts, delivers. Refusals from the messaging service (not_connected, recipient_has_no_key, rate_limited) pass through with `step`. Text only, up to 64 KB (D25).',
          requestBody: {
            required: true,
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  required: ['resource', 'to', 'text'],
                  properties: {
                    resource: { type: 'string', format: 'uri', description: 'The messaging service to deliver through, as an https origin; you and the recipient both have accounts there. llms.txt names the default.' },
                    to: { type: 'string', format: 'uri', description: 'The recipient\'s identifier URI as the messaging service knows it.', example: 'mailto:bob@example.com' },
                    text: { type: 'string', description: 'The message. Up to 64 KB as JSON.' },
                    from: { type: 'string', format: 'uri', description: 'One of your identifier URIs at the messaging service; default your address on that connection.' },
                    idempotency_key: { type: 'string', maxLength: 64, description: 'Passed to the messaging service; a repeat with the same key returns the original message.' },
                  },
                },
              },
            },
          },
          responses: {
            '200': { description: 'Delivered', content: { 'application/json': { schema: { type: 'object', properties: { id: { type: 'string' }, to: { type: 'string' }, from: { type: 'string' }, kid: { type: 'string' }, size: { type: 'integer' }, resource: { type: 'string' }, replayed: { type: 'boolean' } } } } } },
            '400': { description: 'invalid_request (resource, to, text, from, idempotency_key) or attachments_not_supported' },
            '404': { description: 'not_connected, from the messaging service' },
            '409': { description: 'recipient_has_no_key or another refusal from the messaging service' },
            '413': { description: 'text_too_long' },
            '429': { description: 'rate_limited, from the messaging service' },
            '502': { description: 'The chain failed: the Person Server refused a person token for the resource (error is its code), or the resource did not answer. `step` says where.' },
          },
        },
      },
    },
  }
}
