# Threat Model

This model covers the completed CLI/backend. GUI and packaging are out of scope.

| Threat | Impact | Mitigation | Residual risk |
|---|---|---|---|
| Attacker obtains encrypted files | Offline password attacks | Argon2id with random salt and bounded stored costs; AEAD encryption | Weak user passwords remain guessable |
| Ciphertext modification | Corruption or malicious plaintext | Chunked AEAD; publish output only after full authentication | Denial of service remains possible |
| Stolen key files | Data or identity compromise | Encrypted private keys and restricted permissions | Memory and endpoint compromise |
| Weak password | Key recovery by guessing | Secure defaults, guidance, and password tools | User-selected weakness |
| Malicious CRYPTX/CRYPTH file | Parser abuse or resource exhaustion | Exact-field parsing, bounded headers, KDF costs and chunks | Unknown implementation flaws |
| Path traversal | Writes outside intended location | Resolved-path validation and explicit output selection | Authorized local user manipulation |
| Temporary-file leakage | Plaintext disclosure | Avoid plaintext temporary files; atomic encrypted output | OS swap/pagefile may retain data |
| Swap or pagefile exposure | Secret recovery | Minimize secret lifetime and document OS controls | Python cannot guarantee memory locking |
| Terminal history leakage | Secret disclosure | Prompt secrets without echo; never accept them as defaults | User can explicitly expose arguments |
| Log leakage | Secret disclosure | Logging off by default; allow-listed metadata only | Caller misuse requires review and tests |
| Symlink attacks | Unexpected overwrite | Reject source/destination symlinks; no implicit overwrite | Parent-directory replacement remains OS-dependent |
| Partial-write corruption | Lost or invalid output | fsync, same-directory temporary file and atomic publication | Power loss and filesystem behavior vary |
| Malicious certificate | False trust decision | Explicit roots, signatures, validity, CA constraints and SAN matching | No online CRL/OCSP checking |
| Malicious analyzer input | Resource exhaustion or parser abuse | 16 MiB input bound, four-layer decode limit, bounded segment display, established DER parsers | Native dependency parser defects remain possible |
| Misidentified ciphertext | False security conclusion | Confidence labels; representation/container/cipher separation; signatures before heuristics | Unknown and proprietary formats remain ambiguous |
| Misleading entropy result | Incorrect randomness conclusion | No display below 16 bytes; sample-limited maximum below 256 bytes | Entropy alone never proves encryption or quality |
| Vault left open | Secret exposure | Optional inactivity auto-lock and explicit lock | Process compromise before lock |
| Dependency compromise | Arbitrary code execution | Bounded dependencies, pip check, Ruff and Bandit | Registry or build-chain compromise |
