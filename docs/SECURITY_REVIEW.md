# Backend 1.0 Security Review

## Controls verified

- Production primitives come from `cryptography`, libsodium/PyNaCl, Python
  `hashlib`/`hmac`, and `argon2-cffi`; educational code is isolated in `lab`.
- CRYPTX and CRYPTH parsing is versioned, bounded, exact-field, authenticated,
  and rejects truncation and trailing data.
- Decrypted output remains temporary until complete authentication succeeds.
- Existing output is not replaced unless the caller explicitly requests it.
- File sources and destinations reject symbolic links at validation time.
- Private keys use encrypted PKCS#8 and restrictive POSIX modes where available.
- HMAC comparison and checksum comparison use constant-time comparison.
- Logs are disabled by default and accept only operational metadata.
- Passwords are obtained through non-echoing prompts in the CLI.
- Multi-recipient encryption, file hashing, and detached signatures stream data.
- Vaults support inactivity auto-lock and explicit password rotation.
- X.509 validation requires explicit roots and checks time, chain signatures,
  CA constraints, and optional SAN/hostname matching.
- Ruff, Bandit, dependency consistency, malformed input, and large multichunk
  tests are part of the validation procedure.

## Residual risks

Python cannot guarantee erasure of immutable secret objects or memory locking.
Secrets may reach swap, crash dumps, or a compromised endpoint. Hard-link based
atomic publication depends on local filesystem support. Windows profile ACLs
must be correctly configured. No application can protect data after an attacker
controls the running process. Dependency provenance still depends on the Python
package supply chain. Linux runtime behavior is coded portably and configured
in CI; the current local verification was performed on Windows.

The secure-delete command is explicitly best effort. Overwriting cannot be
guaranteed on SSDs, copy-on-write filesystems, snapshots, journaling filesystems,
or synchronized storage. Media sanitization requires OS or hardware procedures.
