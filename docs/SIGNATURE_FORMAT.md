# Detached Signature Format Version 1

`CRYPTSIG 01` contains canonical JSON for an Ed25519, ECDSA P-256, or RSA-PSS
signature. Documents are hashed incrementally with SHA-512. The signature
covers a fixed legacy domain separator and the digest. The signer
algorithm and SHA-256 public-key fingerprint must also match.

This is a Cryptonik-specific format, not CMS, PGP, or interoperable
Ed25519ph.
