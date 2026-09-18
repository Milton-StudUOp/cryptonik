# Cryptographic Format Analyzer

The option 17 analyzer and the `cryptonik analyze` command inspect data without
claiming that visual or statistical characteristics reveal an encryption
algorithm. It is a local format-forensics aid, not a decryption or password
recovery tool.

## Usage

```bash
cryptonik analyze "VALUE"
cryptonik analyze --file encrypted.bin
```

The interactive menu supports pasting a value or selecting a file. Input is
limited to 16 MiB.

## Analysis pipeline

The pipeline preserves evidence in this order:

1. **Representation** — binary byte groups, spaced or continuous hexadecimal,
   Morse, Base64, Base64URL, Base32, URL percent encoding, or raw text/binary.
2. **Recursive decode** — at most four unambiguous layers. Dot-separated
   segments are decoded independently and bounded text values are displayed.
3. **Container signatures** — strong magic values such as `Salted__`, `CRYPTX`,
   `CRYPTH`, `CRYPTSIG`, ZIP, PDF, and PNG.
4. **Structural validation** — PEM/OpenPGP labels, OpenSSH records, DER parsers,
   and compact JOSE structures.
5. **Cryptographic metadata** — algorithms and sizes explicitly present in a
   parsed header; protected contents are not opened without a password.
6. **Statistics** — Shannon entropy only after structural checks.

## Supported cryptographic formats

| Family | Identification |
|---|---|
| Cryptonik | CRYPTX, CRYPTH, CRYPTSIG, encrypted text token |
| OpenSSL | Traditional `Salted__` encrypted container and 8-byte salt presence |
| PEM | Certificates, CSRs, public keys, PKCS#8, PKCS#1, and SEC1 labels |
| OpenPGP | Message, public/private key block, and signature ASCII armor |
| OpenSSH | Ed25519, RSA, Ed448, DSA, and NIST ECDSA public-key records |
| DER | X.509 certificates, SubjectPublicKeyInfo, and PKCS#8 private keys |
| PKCS#12 | Unencrypted PFX contents and password-protected outer structure |
| JOSE | JWT/JWS with validated JSON algorithm header; JWE compact form with `alg` and `enc` |

An encrypted PKCS#8 or PKCS#12 container can be identified, but its protected
metadata cannot be inspected without the password. The analyzer never asks for
that password.

## Confidence model

- **certain**: canonical decoding, explicit label, or successful parser result.
- **high**: strong signature or structurally validated compatibility.
- **low**: size or statistical compatibility that has multiple explanations.
- **unknown**: insufficient evidence.

Three dot-separated encoded values are not automatically a JWT. A JWT/JWS
requires a decodable JSON protected header containing `alg`; JWE compact form
requires five encoded segments and a header containing both `alg` and `enc`.

## Statistical interpretation

For fewer than 16 bytes, statistical output is not shown. From 16 through 255
bytes, the analyzer reports observed entropy together with the sample-limited
maximum `log2(sample size)` and the theoretical 8-bit maximum. At 256 bytes or
more, high entropy may produce only a low-confidence randomness characteristic.

Entropy cannot distinguish encryption from compression, randomness, or some
serialized binary formats. A header identifies a container, not necessarily a
cipher. For example, OpenSSL `Salted__` does not reveal AES, DES, the mode, or
the password derivation parameters.

## Privacy and safety

Analysis is local. Values are not logged; the normal logging subsystem records
only allow-listed operation names and status. Decoded values printed to the
terminal may still be sensitive, so users should protect terminal history and
captured output.
