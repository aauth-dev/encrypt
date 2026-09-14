# Format

encrypt produces the container that decrypt reads: JWE `ECDH-ES` + `A256GCM` on P-256, stored
disassembled as `protected`, `iv`, `tag`, and the raw ciphertext. The specification and the
interop vectors are kept once, in
[decrypt-agent-coop/spec/container.md](https://github.com/aauth-dev/decrypt-agent-coop/blob/main/spec/container.md).

`vectors/` is a copy of that repository's vectors. The tests encrypt each vector's plaintext to
its public key and decrypt the result with the vector's private key using jose; a vector's own
ciphertext cannot be reproduced (ephemeral key and IV are random), so the check is interop, not
byte equality.
