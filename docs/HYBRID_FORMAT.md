# CRYPTH Multi-Recipient Format Version 1

CRYPTH encrypts a file once with XChaCha20-Poly1305 and wraps its random
256-bit data key independently for each recipient. X25519 uses an ephemeral
key, HKDF-SHA256 and ChaCha20-Poly1305 wrapping. RSA uses OAEP-SHA256 with keys
of at least 3072 bits.

The bounded canonical header contains recipient envelopes, a random nonce
prefix, plaintext size, and chunk size. Every chunk authenticates the complete
header plus its 64-bit index. The parser rejects unknown algorithms, malformed
recipients, truncation, invalid lengths, and trailing data. Decrypted output
remains temporary until all chunks authenticate.
