import { defineConfig } from 'vitest/config'
import { cloudflareTest } from '@cloudflare/vitest-plugin'

// Deterministic test keys; the deployed keys are secrets.
const TEST_SIGNING_KEY = JSON.stringify({"crv":"Ed25519","d":"PziIgOYP2lo0Oemy_iRbKFEgIe4kocfMQIKGjQIGv-0","x":"bzBPDoo8y1MVySZiwpAJJJ0dFxdBYbb0UMPKj0_jmao","kty":"OKP","alg":"Ed25519"})
const TEST_AGENT_KEY = JSON.stringify({"crv":"Ed25519","d":"rJY5TCP27fRqKKP61WOyCcivxPN1SRWqsVQ6Z5N4mno","x":"KAi9p0ZVmW2qWSrLpw1FSLvGNW9OR7BmuME3_7UukqY","kty":"OKP","alg":"Ed25519"})

export default defineConfig({
  plugins: [
    cloudflareTest({
      wrangler: { configPath: './wrangler.jsonc' },
      miniflare: { bindings: { SIGNING_KEY: TEST_SIGNING_KEY, AGENT_KEY: TEST_AGENT_KEY } },
    }),
  ],
  test: { include: ['test/**/*.test.ts'] },
})
