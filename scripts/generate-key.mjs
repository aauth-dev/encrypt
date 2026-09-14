// Generate an Ed25519 signing key for SIGNING_KEY. Prints the private JWK
// (one line) for `wrangler secret put SIGNING_KEY`.
import { generateKeyPair, exportJWK } from 'jose'
const { privateKey } = await generateKeyPair('Ed25519', { extractable: true })
const jwk = await exportJWK(privateKey)
console.log(JSON.stringify({ ...jwk, alg: 'Ed25519' }))
