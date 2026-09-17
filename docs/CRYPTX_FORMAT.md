# CRYPTX Format Version 1

CRYPTX is a container format, not a cryptographic algorithm. Version 1 stores
password-encrypted files as independently authenticated chunks.

## Framing

1. Six-byte ASCII magic: `CRYPTX`
2. One-byte version: `01`
3. Four-byte big-endian JSON header length
4. Canonical ASCII JSON header, limited to 16 KiB
5. Repeated chunks: four-byte ciphertext length followed by AEAD ciphertext

The authenticated header declares the AEAD, Argon2id parameters, random salt,
random nonce prefix, chunk size, and plaintext size. Every chunk authenticates
the complete serialized header plus its unsigned 64-bit index. Its nonce is the
random prefix followed by that index. This binds ordering, detects missing and
repeated chunks, and prevents header substitution.

Chunk sizes are restricted to 64 KiB–16 MiB. Header fields are exact: unknown
or missing fields, algorithms, KDFs, versions, malformed encodings, invalid
lengths, truncated input, and trailing data are rejected. Decryption writes to
a same-directory temporary file and publishes it only after every chunk has
authenticated.

Version 1 deliberately omits filenames and timestamps, avoiding plaintext
metadata leakage. It supports Argon2id with AES-256-GCM, ChaCha20-Poly1305, or
XChaCha20-Poly1305. It is not asserted to be compatible with any external file
format.
