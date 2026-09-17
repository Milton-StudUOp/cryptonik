# Cryptonik

Cryptonik 1.0 is a local cryptography and security toolkit for Windows and
Linux. This repository contains the complete CLI/backend. A GUI and native
executable packaging are intentionally excluded.

## Features

- AES-256-GCM, ChaCha20-Poly1305, and XChaCha20-Poly1305
- Argon2id password-based key derivation with bounded parameters
- Streaming CRYPTX password-encrypted files
- Streaming CRYPTH X25519/RSA multi-recipient files
- SHA-2, SHA-3, BLAKE2, HMAC, integrity checking, and encoding
- Ed25519, ECDSA P-256, and RSA-PSS streaming detached signatures
- Protected Ed25519, X25519, ECDSA, and RSA key store
- Encrypted vault with auto-lock, backup, password rotation, and file entries
- X.509 inspection, CSR/self-signed generation, and offline trust validation
- Secure random/password generators and measured local benchmarks
- Isolated educational classical cryptography and cryptanalysis lab
- Conservative ciphertext/encoding/container analyzer with explicit confidence
- Functional interactive menu and direct command-line interface

Production primitives are supplied by `cryptography`, libsodium/PyNaCl,
`argon2-cffi`, `hashlib`, and `hmac`. Educational implementations are isolated
under `cryptosuite.lab` and explicitly marked as unsuitable for real security.

## Requirements and installation

- Python 3.12 or newer
- Windows 10/11 or a current Linux distribution

Windows PowerShell:

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install -e ".[dev]"
```

The installed command is `cryptonik`. The former `cryptosuite` command remains
available as a compatibility alias.

Linux:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e ".[dev]"
```

## Interactive menu

```bash
python main.py
```

All 17 categories open guided workflows. `--help` is a shell argument, not a
menu selection.

## CLI quick start

```bash
python main.py --help
python main.py encrypt document.pdf
python main.py decrypt document.pdf.cryptx --output restored.pdf
python main.py hash document.pdf --algorithm sha256
python main.py compare-hashes HASH_A HASH_B
python main.py integrity document.pdf EXPECTED_SHA256
python main.py hmac generate "message"
python main.py random --bytes 32 --format base64
python main.py password --length 40
python main.py encoding encode base64 "Hello"
python main.py analyze "PASTE_VALUE_HERE"
python main.py analyze --file encrypted.bin
```

The analyzer recognizes Cryptonik containers and text tokens, OpenSSL `Salted__`,
PEM, OpenSSH Ed25519 keys, JWT, ZIP, PDF, PNG, strict hex/Base64/Base32 encodings,
binary byte groups, spaced hexadecimal bytes, Morse, URL encoding, dot-separated
structures, and hash-sized values. It recursively inspects up to four unambiguous
decode layers. Strong format signatures are evaluated before statistical heuristics.
Small samples are explicitly rejected for entropy-based classification. Cipher
algorithms cannot generally be identified from ciphertext alone.

## Public-key files and signatures

```bash
python main.py public-key encrypt secret.bin \
  --recipient alice-public.pem --recipient bob-public.pem
python main.py public-key decrypt secret.bin.crypth \
  --key alice-private.pem --output restored.bin
python main.py sign contract.pdf --key signing-private.pem
python main.py verify contract.pdf contract.pdf.sig --key signing-public.pem
```

CRYPTX, CRYPTH, and detached signature formats are documented under `docs/`.
Existing output is never replaced unless `--force` or explicit interactive
confirmation is used.

## Key management

```bash
python main.py keys generate --type ed25519 --name "Signing" --purpose signing
python main.py keys list
python main.py keys info KEY-ID
python main.py keys show-public KEY-ID --output public.pem
python main.py keys import private.pem --name "Imported" --purpose signing
python main.py keys import-public recipient.pem --name "Alice" --purpose key-exchange
python main.py keys export-private KEY-ID protected-backup.pem
python main.py keys backup KEY-ID backup.pem
python main.py keys change-password KEY-ID
python main.py keys delete KEY-ID
```

Private keys are stored as encrypted PKCS#8. The default store is next to the
configuration file.

## Vault

```bash
python main.py vault create secrets.vault
python main.py vault add secrets.vault --kind api-key --name Example
python main.py vault add-file secrets.vault small.bin
python main.py vault list secrets.vault
python main.py vault show secrets.vault ENTRY-ID
python main.py vault extract secrets.vault ENTRY-ID restored.bin
python main.py vault backup secrets.vault backup.vault
python main.py vault change-password secrets.vault
python main.py vault delete secrets.vault ENTRY-ID
```

Losing the master password makes recovery impossible.

## Certificates

```bash
python main.py certificate inspect server.crt
python main.py certificate csr --key private.pem \
  --common-name example.test --san example.test --output request.csr
python main.py certificate self-signed --key private.pem \
  --common-name example.test --san example.test --output certificate.pem
python main.py certificate validate certificate.pem \
  --ca trusted-root.pem --hostname example.test
```

Validation is offline against explicitly supplied roots. Online CRL and OCSP
checking are not performed.

## Crypto Lab

Use `python main.py lab --help`. The lab includes Caesar, Vigenere, Affine,
Rail Fence, Playfair, Hill 2x2, frequency analysis, entropy, avalanche, textbook
RSA, unauthenticated Diffie-Hellman, number theory, and legacy MD5/SHA-1.
Legacy and classical operations always display educational warnings.

## Configuration and logging

- Windows: `%APPDATA%\Cryptonik\config.json`
- Linux: `$XDG_CONFIG_HOME/cryptonik/config.json` or
  `~/.config/cryptonik/config.json`

Override with `CRYPTONIK_CONFIG_DIR`. Existing `CryptoSuite` configuration
directories and the legacy `CRYPTOSUITE_CONFIG_DIR` variable are detected for
backward compatibility. Logging is disabled by default and
records only allow-listed operation names and status, never arguments, keys,
passwords, plaintext, or vault values.

## Security model

Read:

- `docs/CRYPTO_CORE.md`
- `docs/CRYPTX_FORMAT.md`
- `docs/HYBRID_FORMAT.md`
- `docs/SIGNATURE_FORMAT.md`
- `docs/THREAT_MODEL.md`
- `docs/SECURITY_REVIEW.md`

Best-effort secure deletion cannot guarantee erasure on SSDs, snapshots,
copy-on-write filesystems, backups, or synchronized storage.

## Development and testing

```bash
python -m pytest --cov=cryptosuite
python -m ruff check .
python -m bandit -r cryptosuite -q
python -m pip check
```

The included CI matrix runs on Windows and Ubuntu with Python 3.12 and 3.13.
