# Architecture

Cryptonik uses a layered architecture. `cli` is a thin adapter over shared
domain services. `core` owns production cryptographic
operations and only calls established libraries. The forensic analyzer in
`core.analyzer` classifies representations before containers and structural
metadata; it uses established parsers for cryptographic DER objects. `files`, `keys`,
`certificates`, and `vault` own their respective workflows. `lab` is physically
separate and contains only conspicuously labelled educational implementations.

Dependencies point inward: interfaces call domain services; domain services
may use shared utilities; production services never call educational code.
Configuration contains preferences only, never cryptographic secrets.

The analyzer pipeline is deliberately ordered:

1. classify the input representation;
2. decode bounded, unambiguous layers;
3. match strong magic values and container signatures;
4. validate structures such as JWT/JWS/JWE and DER objects;
5. expose non-secret cryptographic metadata; and
6. apply statistical heuristics last.

Recursive decoding is limited to four layers, input is capped at 16 MiB, and
decoded segment text is capped for display. A format match never implies a
specific cipher unless authenticated metadata explicitly supplies it.

The implemented CRYPTX and CRYPTH parsers treat all input as hostile. Both use
versioned, bounded formats, authenticate metadata, reject unknown identifiers,
and publish output atomically only after successful authentication. CRYPTX is
password-based; CRYPTH wraps one random data key for one or more X25519 or
RSA-3072 recipients. Both stream independently authenticated chunks.

# Cross-platform strategy

Paths use `pathlib`. User data follows `%APPDATA%` on Windows and the XDG base
directory convention on Linux. The code avoids shell-specific behavior and
uses Python filesystem primitives. Atomic replacement uses `os.replace` on the
same volume. Permission hardening is applied where the operating system exposes
POSIX modes. Windows relies on the user's profile ACLs. CI exercises Windows
and Ubuntu; native executable packaging remains outside the current scope.
