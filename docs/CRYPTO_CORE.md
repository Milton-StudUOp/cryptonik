# Crypto Core

The crypto core provides byte-oriented APIs shared by all file, CLI, vault,
key, and certificate workflows. Container formats are documented separately.

## Algorithms

- Hashes: SHA-256, SHA-384, SHA-512, SHA3-256, SHA3-512, BLAKE2b, BLAKE2s
- Message authentication: HMAC-SHA256, HMAC-SHA512
- Password KDF: Argon2id version 1.3
- AEAD: AES-256-GCM, ChaCha20-Poly1305, XChaCha20-Poly1305
- Random generation: the Python `secrets` interface to the operating-system
  CSPRNG

AES-GCM and ChaCha20-Poly1305 are provided by `cryptography`. XChaCha20-
Poly1305 is provided by libsodium through PyNaCl. Argon2id is provided by
`argon2-cffi`. No production primitive is implemented manually.

## Safety properties

All symmetric keys are exactly 256 bits. Nonces are generated for every
encryption call unless an advanced caller supplies one. Supplying a nonce puts
uniqueness responsibility on that caller. AES-GCM and ChaCha20-Poly1305 use
96-bit nonces; XChaCha20-Poly1305 uses 192-bit nonces.

Associated data is authenticated but not encrypted. A wrong key, modified
ciphertext, modified tag, or different associated data raises
`AuthenticationError`; unauthenticated plaintext is never returned.

Argon2id defaults to three iterations, 64 MiB memory, four lanes, a 128-bit
salt, and a 256-bit result. Applications must store the salt and exact cost
parameters beside the ciphertext. Passwords and derived keys must never be
logged.

## Internal example

```python
from cryptosuite.core import CryptoEngine, SymmetricAlgorithm

key = CryptoEngine.generate_symmetric_key()
encrypted = CryptoEngine.encrypt(
    b"secret",
    key,
    SymmetricAlgorithm.XCHACHA20_POLY1305,
    associated_data=b"authenticated metadata",
)
plaintext = CryptoEngine.decrypt(
    encrypted,
    key,
    associated_data=b"authenticated metadata",
)
```
