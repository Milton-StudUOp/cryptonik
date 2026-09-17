# PROJETO: CRYPTOSUITE — APLICAÇÃO COMPLETA DE CRIPTOGRAFIA PARA WINDOWS E LINUX

## 1. OBJETIVO

Desenvolver uma aplicação completa de criptografia denominada **CryptoSuite**, escrita principalmente em **Python 3**, destinada a executar localmente em:

* Linux
* Windows

A aplicação deve funcionar sem servidor web, sem cloud e sem necessidade de ligação à Internet.

O objetivo é criar simultaneamente:

1. Uma ferramenta prática para operações criptográficas modernas.
2. Um laboratório completo para estudo de Cryptography.
3. Uma ferramenta de análise de hashes, chaves, certificados e dados criptográficos.
4. Um ambiente educacional para compreender algoritmos clássicos e modernos.
5. Uma base extensível para adicionar futuramente novos algoritmos, protocolos e ferramentas.

A segurança deve ter prioridade sobre conveniência.

Algoritmos criptográficos modernos NÃO devem ser implementados manualmente. Devem ser utilizadas bibliotecas criptográficas consolidadas.

Algoritmos implementados manualmente devem existir exclusivamente dentro do módulo educacional Crypto Lab.

---

# 2. TECNOLOGIAS

Utilizar:

* Python 3.12+
* cryptography
* PyNaCl/libsodium quando necessário
* hashlib
* hmac
* secrets
* os
* pathlib
* argparse
* getpass
* base64
* binascii
* json
* struct
* tempfile
* logging

Para interface gráfica desktop, quando implementada:

* PySide6

A arquitetura deve permitir utilizar toda a aplicação inicialmente pela CLI.

Exemplo:

```bash
python cryptosuite.py
```

Também deverá suportar comandos diretos:

```bash
python cryptosuite.py encrypt file.txt
python cryptosuite.py decrypt file.txt.cryptx
python cryptosuite.py hash file.iso
python cryptosuite.py keys generate
python cryptosuite.py sign document.pdf
python cryptosuite.py verify document.pdf
```

Posteriormente deverá ser possível gerar executáveis independentes.

Windows:

```text
CryptoSuite.exe
```

Linux:

```text
cryptosuite
```

---

# 3. PRINCÍPIOS DE SEGURANÇA

Nunca inventar primitivas criptográficas próprias para funcionalidades reais.

Utilizar exclusivamente algoritmos modernos e bibliotecas reconhecidas.

Implementar:

* CSPRNG
* Nonces únicos
* Salts aleatórios
* Authenticated Encryption
* Password-Based Key Derivation
* Comparação constant-time quando necessária
* Validação rigorosa de inputs
* Tratamento seguro de erros
* Proteção contra path traversal
* Escrita atómica de ficheiros
* Verificação de integridade
* Versionamento do formato criptográfico

Nunca:

* armazenar passwords em plaintext;
* gravar chaves privadas em logs;
* reutilizar nonce onde isso comprometa o algoritmo;
* utilizar `random` para geração criptográfica;
* utilizar ECB;
* utilizar MD5/SHA-1 para segurança;
* criar AES, RSA ou ECC manualmente para produção;
* guardar plaintext temporário desnecessariamente;
* apresentar chaves secretas no terminal sem solicitação explícita.

---

# 4. ARQUITETURA

Criar uma arquitetura modular:

```text
cryptosuite/
│
├── main.py
├── cli.py
├── config.py
│
├── core/
│   ├── symmetric.py
│   ├── asymmetric.py
│   ├── hashing.py
│   ├── hmac_tools.py
│   ├── signatures.py
│   ├── kdf.py
│   ├── random_generator.py
│   ├── encoding.py
│   └── crypto_engine.py
│
├── files/
│   ├── encrypt_file.py
│   ├── decrypt_file.py
│   ├── file_format.py
│   ├── secure_delete.py
│   └── integrity.py
│
├── keys/
│   ├── key_manager.py
│   ├── key_generator.py
│   ├── key_import.py
│   ├── key_export.py
│   └── key_store.py
│
├── certificates/
│   ├── certificate_parser.py
│   ├── certificate_generator.py
│   └── certificate_validator.py
│
├── vault/
│   ├── vault.py
│   ├── vault_database.py
│   └── vault_manager.py
│
├── lab/
│   ├── caesar.py
│   ├── vigenere.py
│   ├── affine.py
│   ├── hill.py
│   ├── rail_fence.py
│   ├── frequency_analysis.py
│   ├── entropy.py
│   ├── avalanche.py
│   ├── rsa_demo.py
│   └── diffie_hellman_demo.py
│
├── utils/
│   ├── validators.py
│   ├── secure_io.py
│   ├── formatters.py
│   └── exceptions.py
│
├── gui/
│   └── ...
│
├── tests/
│   └── ...
│
├── requirements.txt
├── pyproject.toml
├── README.md
└── LICENSE
```

Não colocar toda a aplicação num único script.

---

# 5. MENU PRINCIPAL

Ao executar:

```bash
python main.py
```

apresentar:

```text
==================================================
                 CRYPTOSUITE
          Cryptography & Security Toolkit
==================================================

[1] Encrypt / Decrypt
[2] File Encryption
[3] Hashing
[4] HMAC
[5] Digital Signatures
[6] Public-Key Cryptography
[7] Key Management
[8] Password & KDF Tools
[9] Random Generator
[10] Encoding / Decoding
[11] Integrity Checker
[12] Certificates
[13] Secure Vault
[14] Crypto Lab
[15] Benchmark
[16] Settings
[0] Exit
```

A interface CLI deve ser organizada, legível e consistente entre Windows e Linux.

---

# 6. CRIPTOGRAFIA SIMÉTRICA

Implementar suporte seguro para:

* AES-256-GCM
* ChaCha20-Poly1305
* XChaCha20-Poly1305, quando suportado pela biblioteca utilizada

Permitir:

* criptografar texto;
* criptografar bytes;
* criptografar ficheiros;
* decrypt;
* password-based encryption;
* key-based encryption.

Nunca utilizar AES-ECB.

CBC poderá existir exclusivamente no Crypto Lab para fins educacionais.

---

# 7. CRIPTOGRAFIA DE FICHEIROS

Implementar:

```bash
cryptosuite encrypt documento.pdf
```

Resultado:

```text
documento.pdf.cryptx
```

Decrypt:

```bash
cryptosuite decrypt documento.pdf.cryptx
```

O programa deve suportar ficheiros grandes sem carregar todo o conteúdo para RAM.

Implementar processamento por blocos/streaming quando apropriado.

Mostrar:

```text
Encrypting: backup.zip

Algorithm : XChaCha20-Poly1305
KDF       : Argon2id
Size      : 8.42 GB

Progress:
████████████████░░░░ 81%

Speed: 142 MB/s
```

Nunca sobrescrever automaticamente o ficheiro original.

Solicitar confirmação ou utilizar argumento explícito.

---

# 8. FORMATO .CRYPTX

Criar formato próprio versionado para encapsular os dados, mas NÃO criar algoritmo criptográfico próprio.

Estrutura conceitual:

```text
CRYPTX
│
├── Magic
├── Format Version
├── Algorithm ID
├── KDF ID
├── Salt
├── Nonce/Header
├── Parameters
├── Metadata
├── Ciphertext
└── Authentication Data
```

Magic:

```text
CRYPTX
```

Versão inicial:

```text
01
```

O parser deve rejeitar:

* versões desconhecidas;
* algoritmos desconhecidos;
* headers corrompidos;
* parâmetros inválidos;
* ficheiros truncados.

Metadata sensível deverá ser autenticada e, quando necessário, criptografada.

---

# 9. PASSWORD-BASED ENCRYPTION

Nunca utilizar diretamente:

```text
SHA256(password)
```

para produzir encryption keys.

Implementar:

```text
Password
    │
    ↓
Random Salt
    │
    ↓
Argon2id
    │
    ↓
256-bit Key
    │
    ↓
Authenticated Encryption
```

Permitir configuração segura dos parâmetros Argon2id.

Mostrar estimativa de custo computacional quando apropriado.

---

# 10. HASHING

Implementar:

* SHA-256
* SHA-384
* SHA-512
* SHA-3
* BLAKE2b
* BLAKE2s

Exemplo:

```bash
cryptosuite hash ubuntu.iso --algorithm sha256
```

Resultado:

```text
SHA-256

File:
ubuntu.iso

Hash:
8F14E45FCEEA167A5A36DEDD4BEA2543...
```

Permitir comparar dois hashes.

---

# 11. LEGACY HASH LAB

MD5 e SHA-1 poderão existir somente no módulo educacional/compatibilidade.

Mostrar claramente:

```text
WARNING

MD5 is cryptographically broken.

Do not use MD5 for:
- passwords
- signatures
- certificates
- security verification
```

---

# 12. HMAC

Implementar:

* HMAC-SHA256
* HMAC-SHA512

Permitir:

```text
Generate HMAC
Verify HMAC
```

A verificação deverá utilizar comparação constant-time.

---

# 13. DIGITAL SIGNATURES

Implementar prioritariamente:

* Ed25519

E, quando necessário:

* RSA-PSS
* ECDSA

Permitir:

```bash
cryptosuite sign contract.pdf --key private.pem
```

Gerar:

```text
contract.pdf.sig
```

Verificação:

```bash
cryptosuite verify contract.pdf contract.pdf.sig --key public.pem
```

Resultado:

```text
DIGITAL SIGNATURE

Algorithm:
Ed25519

Status:
VALID
```

ou:

```text
INVALID
```

Nunca modificar o documento original.

---

# 14. PUBLIC-KEY CRYPTOGRAPHY

Implementar:

* X25519
* Ed25519
* RSA para interoperabilidade
* ECC quando apropriado

Separar claramente:

```text
Encryption keys
Signing keys
Key-exchange keys
```

Não reutilizar automaticamente uma mesma chave para finalidades criptográficas diferentes.

---

# 15. HYBRID ENCRYPTION

Para criptografia assimétrica de ficheiros utilizar arquitetura híbrida.

```text
Random symmetric key
          │
          ↓
     Encrypt file
          │
          ↓
      Ciphertext

Random symmetric key
          │
          ↓
Recipient Public Key
          │
          ↓
Encrypted/Encapsulated Key
```

Não criptografar ficheiros grandes diretamente com RSA.

---

# 16. MULTIPLE RECIPIENTS

Permitir criptografar um ficheiro para múltiplos destinatários:

```text
secret.cryptx

Recipients:

Alice
Bob
Carlos
Milton
```

Cada destinatário poderá recuperar a data-encryption key usando sua própria chave privada.

---

# 17. KEY MANAGEMENT

Criar Key Manager completo.

Funções:

```text
Generate Key
Import Key
Export Key
List Keys
Show Public Key
Backup Key
Delete Key
Change Protection Password
Key Information
```

Cada chave deverá possuir:

```text
ID
Name
Algorithm
Purpose
Created
Public fingerprint
Status
```

Exemplo:

```text
Key ID:
9A4C-F817-229A

Algorithm:
Ed25519

Created:
2026-09-17

Fingerprint:
A4:71:93:AF:...
```

---

# 18. PRIVATE KEY PROTECTION

Chaves privadas armazenadas em disco devem ser protegidas.

Nunca:

```text
private_key.pem
```

sem proteção por defeito.

Utilizar criptografia baseada em password ou armazenamento seguro apropriado ao sistema operacional.

Definir permissões restritivas no Linux.

---

# 19. KEY FINGERPRINT

Implementar fingerprints para facilitar identificação e comparação de public keys.

Mostrar:

```text
SHA-256 fingerprint:

3A:91:FF:82:4C:...
```

---

# 20. RANDOM GENERATOR

Criar gerador criptograficamente seguro para:

```text
Random bytes
Encryption keys
Tokens
UUIDs
Passwords
Hex values
Base64 values
```

Utilizar:

```python
secrets
```

ou CSPRNG fornecido pela biblioteca criptográfica.

Nunca utilizar:

```python
random.random()
```

para material criptográfico.

---

# 21. PASSWORD GENERATOR

Permitir gerar passwords configuráveis.

Exemplo:

```text
Length: 32

Character sets:
[x] Uppercase
[x] Lowercase
[x] Numbers
[x] Symbols
```

Mostrar também estimativas educacionais de entropia, deixando claro quando forem apenas aproximações.

---

# 22. ENCODING TOOLS

Implementar:

```text
Base64
Base32
Hex
UTF-8
URL-safe Base64
```

Separar claramente:

```text
ENCODING != ENCRYPTION
```

---

# 23. FILE INTEGRITY CHECKER

Permitir verificar integridade:

```bash
cryptosuite integrity ubuntu.iso checksum.txt
```

Resultado:

```text
Expected:
ABC123...

Calculated:
ABC123...

STATUS:
MATCH
```

---

# 24. CERTIFICATE TOOLS

Implementar análise de certificados X.509.

Permitir abrir:

```text
.pem
.crt
.cer
```

Mostrar:

```text
Subject
Issuer
Serial Number
Validity
Public Key
Signature Algorithm
SAN
Key Usage
Extended Key Usage
Fingerprint
```

Quando suportado de forma confiável, permitir gerar:

* private key;
* CSR;
* self-signed certificate.

---

# 25. SECURE VAULT

Criar um cofre criptografado local.

Permitir armazenar:

```text
Text notes
Passwords
API keys
Tokens
Small files
Cryptographic keys
```

Arquitetura:

```text
Master Password
      ↓
Argon2id
      ↓
Master Key
      ↓
Authenticated Encryption
      ↓
Encrypted Vault
```

Nunca armazenar master password.

Implementar auto-lock opcional.

---

# 26. CRYPTO LAB

Criar módulo educacional separado.

Menu:

```text
CRYPTO LAB

[1] Classical Cryptography
[2] Symmetric Cryptography
[3] Public-Key Cryptography
[4] Hash Functions
[5] Key Exchange
[6] Cryptanalysis
[7] Entropy
[8] Avalanche Effect
[9] Number Theory
[10] Encoding
```

---

# 27. CLASSICAL CRYPTOGRAPHY

Implementar para estudo:

* Caesar Cipher
* Vigenère Cipher
* Affine Cipher
* Rail Fence
* Playfair
* Hill Cipher

Permitir visualizar passo a passo como cada algoritmo transforma a mensagem.

Mostrar:

```text
EDUCATIONAL ALGORITHM

This cipher is NOT secure for modern cryptographic use.
```

---

# 28. RSA LAB

Criar implementação educacional de RSA separada da implementação segura utilizada pela aplicação.

Permitir visualizar:

```text
Choose primes p and q

p = 61
q = 53

n = p × q
n = 3233

φ(n) = 3120

e = 17

d = 2753
```

Mostrar passo a passo:

```text
Key Generation
Encryption
Decryption
Modular Arithmetic
```

Essa implementação nunca deverá ser utilizada para proteger dados reais.

---

# 29. DIFFIE-HELLMAN LAB

Criar demonstração visual:

```text
Alice                    Bob

Private A                Private B
   │                         │
   ↓                         ↓

Public A                 Public B
       \                 /
        \               /
          Key Exchange
               ↓
          Shared Secret
```

Explicar também por que Diffie-Hellman sem autenticação é vulnerável a MITM.

---

# 30. FREQUENCY ANALYSIS

Criar ferramenta para análise de frequência.

Entrada:

```text
Ciphertext
```

Saída:

```text
A █████████████ 13.2%
E ███████████   11.1%
T █████████      9.4%
...
```

Permitir análise de:

* caracteres;
* bigramas;
* trigramas.

---

# 31. AVALANCHE EFFECT

Permitir comparar:

```text
Message 1:
Hello World

Message 2:
hello World
```

Calcular os hashes e mostrar quantos bits foram alterados.

Apresentar:

```text
Changed bits:
128 / 256

Difference:
50.0%
```

---

# 32. ENTROPY ANALYSIS

Criar módulo para analisar dados e ficheiros.

Calcular:

```text
Shannon entropy
Byte distribution
Frequency
File size
```

Não afirmar automaticamente que alta entropia significa criptografia.

---

# 33. BENCHMARK

Permitir comparar desempenho local dos algoritmos.

Exemplo:

```text
Algorithm              Throughput

AES-256-GCM             1.8 GB/s
ChaCha20-Poly1305       720 MB/s
SHA-256                 2.1 GB/s
SHA-512                 1.4 GB/s
```

Os valores deverão ser medidos na máquina atual, nunca hardcoded.

---

# 34. LOGGING

Implementar logging seguro.

Permitido:

```text
2026-09-17 12:30
Operation: Encrypt File
Algorithm: AES-256-GCM
Status: Success
```

Nunca registrar:

```text
password
private key
symmetric key
plaintext
decrypted vault contents
```

Permitir desligar completamente o histórico.

---

# 35. ERROR HANDLING

Nunca apresentar stack traces técnicos ao utilizador por padrão.

Exemplo:

```text
ERROR

Unable to decrypt file.

Possible causes:
- Incorrect password
- Corrupted file
- Authentication failure
```

Modo developer/debug poderá apresentar informações adicionais, mas nunca secrets.

---

# 36. TESTES

Criar testes automatizados para todos os módulos críticos.

Utilizar:

```text
pytest
```

Testar:

```text
Encryption → Decryption
Signature → Verification
Correct password
Wrong password
Corrupted ciphertext
Modified authentication tag
Invalid nonce
Invalid key
Truncated file
Large file
Empty file
Unicode
Binary data
Key import/export
CRYPTX parser
```

Utilizar official/test vectors sempre que disponíveis.

---

# 37. SECURITY TESTS

Criar testes específicos para garantir:

```text
Modified ciphertext → FAIL
Modified authentication tag → FAIL
Wrong password → FAIL
Wrong private key → FAIL
Modified signed document → INVALID
Truncated CRYPTX → FAIL
Malformed header → FAIL
```

Falhas de autenticação nunca deverão produzir plaintext considerado válido.

---

# 38. CROSS-PLATFORM

Garantir funcionamento em:

```text
Windows 10
Windows 11
Linux Ubuntu
Linux Debian
Linux Mint
```

Evitar paths hardcoded.

Utilizar:

```python
pathlib.Path
```

---

# 39. EXECUTÁVEL WINDOWS

Preparar posteriormente build com PyInstaller ou ferramenta equivalente.

Resultado:

```text
dist/
└── CryptoSuite.exe
```

O utilizador não deverá precisar instalar Python.

---

# 40. EXECUTÁVEL LINUX

Permitir gerar distribuição executável:

```bash
./cryptosuite
```

Também manter suporte:

```bash
python3 main.py
```

---

# 41. GUI DESKTOP

Somente depois da CLI e Crypto Engine estarem estáveis, criar interface gráfica utilizando PySide6.

A GUI deverá reutilizar exatamente o mesmo Crypto Engine.

Arquitetura:

```text
              Crypto Engine
              /           \
             /             \
           CLI             GUI
```

Nunca duplicar a implementação criptográfica entre CLI e GUI.

---

# 42. DOCUMENTAÇÃO

Criar README completo contendo:

```text
Installation
Requirements
Quick Start
CLI Commands
Encryption
File Encryption
Hashing
Signatures
Key Management
Vault
Certificates
Crypto Lab
Security Model
Threat Model
CRYPTX Format
Development
Testing
Building Windows executable
Building Linux executable
```

---

# 43. THREAT MODEL

Criar documento:

```text
docs/THREAT_MODEL.md
```

Identificar pelo menos:

```text
Attacker obtains encrypted file
Attacker modifies ciphertext
Attacker steals key files
Weak user password
Malicious CRYPTX file
Path traversal
Temporary-file leakage
Swap/pagefile exposure
Terminal history leakage
Log leakage
Symlink attacks
Partial-write corruption
Dependency compromise
```

Para cada ameaça documentar:

```text
Threat
Impact
Mitigation
Residual Risk
```

---

# 44. DESENVOLVIMENTO POR FASES

Não desenvolver tudo de uma vez.

## FASE 1 — FOUNDATION

Criar:

* estrutura do projeto;
* ambiente virtual;
* dependencies;
* CLI;
* configuration;
* exceptions;
* logging;
* testes básicos.

Executar os testes.

Parar e apresentar os resultados.

---

## FASE 2 — CRYPTO CORE

Implementar:

* CSPRNG;
* SHA-256;
* SHA-512;
* BLAKE2;
* HMAC;
* Argon2id;
* AES-256-GCM;
* ChaCha20-Poly1305;
* XChaCha20-Poly1305 quando disponível.

Criar testes.

Parar e apresentar os resultados.

---

## FASE 3 — FILE ENCRYPTION

Implementar:

* formato CRYPTX;
* encryption;
* decryption;
* password encryption;
* large-file handling;
* integrity/authentication;
* progress indicator.

Criar testes.

Parar.

---

## FASE 4 — KEY MANAGEMENT

Implementar:

* key generation;
* key IDs;
* fingerprints;
* import;
* export;
* encrypted private keys;
* key store.

Testar.

Parar.

---

## FASE 5 — PUBLIC-KEY CRYPTO

Implementar:

* X25519;
* Ed25519;
* RSA-PSS;
* hybrid encryption;
* multiple recipients.

Testar.

Parar.

---

## FASE 6 — DIGITAL SIGNATURES

Implementar:

* sign file;
* verify file;
* detached signatures;
* public-key fingerprints.

Testar.

Parar.

---

## FASE 7 — VAULT

Implementar:

* encrypted vault;
* master password;
* Argon2id;
* authenticated encryption;
* auto-lock;
* backup.

Testar.

Parar.

---

## FASE 8 — CERTIFICATES

Implementar:

* X.509 parser;
* certificate information;
* fingerprints;
* CSR generation;
* self-signed certificates.

Testar.

Parar.

---

## FASE 9 — CRYPTO LAB

Implementar:

* Caesar;
* Vigenère;
* Affine;
* Hill;
* Rail Fence;
* RSA demonstration;
* Diffie-Hellman demonstration;
* frequency analysis;
* entropy;
* avalanche effect.

Testar.

Parar.

---

## FASE 10 — HARDENING

Realizar:

* security review;
* malformed-input testing;
* large-file tests;
* corruption tests;
* permissions review;
* temporary-file review;
* dependency review;
* static analysis;
* threat-model review.

Corrigir todas as vulnerabilidades encontradas.

---

## FASE 11 — GUI

Criar GUI desktop PySide6.

Implementar:

```text
Dashboard
Encrypt/Decrypt
Files
Hashes
Signatures
Keys
Certificates
Vault
Crypto Lab
Settings
```

A GUI deve apenas consumir as APIs internas existentes.

---

## FASE 12 — RELEASE

Gerar:

```text
Windows executable
Linux executable
requirements.txt
pyproject.toml
documentation
tests
release package
```

---

# 45. REGRA DE EXECUÇÃO DO DESENVOLVIMENTO

Durante o desenvolvimento:

1. Implementar apenas uma fase de cada vez.
2. Não avançar automaticamente para a próxima fase.
3. Mostrar todos os ficheiros criados ou modificados.
4. Explicar brevemente a função de cada componente.
5. Executar testes reais.
6. Corrigir erros encontrados.
7. Apresentar o resultado dos testes.
8. Apresentar os comandos necessários para executar.
9. Parar.
10. Esperar autorização para continuar.

Não utilizar pseudocódigo quando for solicitada implementação.

Produzir código completo, funcional e organizado.

Não substituir implementações críticas por comentários como:

```python
# TODO
```

ou:

```python
# implement later
```

---

# 46. REQUISITOS DE QUALIDADE

Todo código deve:

* utilizar type hints;
* possuir docstrings onde forem úteis;
* seguir PEP 8;
* evitar duplicação;
* possuir tratamento de exceções;
* validar inputs;
* separar UI de lógica;
* possuir testes;
* ser legível;
* ser modular;
* ser extensível;
* funcionar em Windows e Linux.

Utilizar abstrações somente quando trouxerem benefício real.

---

# 47. REGRA CRÍTICA

A CryptoSuite NÃO deverá criar primitivas criptográficas próprias para proteger dados reais.

O projeto poderá implementar algoritmos manualmente somente dentro de:

```text
lab/
```

e estes deverão estar marcados explicitamente:

```text
EDUCATIONAL IMPLEMENTATION
NOT FOR PRODUCTION USE
```

Todas as funcionalidades reais deverão utilizar bibliotecas criptográficas reconhecidas e algoritmos modernos.

---

# 48. RESULTADO FINAL ESPERADO

Ao concluir o projeto deverá ser possível executar operações como:

```bash
cryptosuite encrypt secret.pdf
cryptosuite decrypt secret.pdf.cryptx

cryptosuite hash ubuntu.iso --algorithm sha256

cryptosuite keys generate --type ed25519

cryptosuite sign contract.pdf --key mykey

cryptosuite verify contract.pdf contract.pdf.sig

cryptosuite random --bytes 32

cryptosuite certificate inspect server.crt

cryptosuite vault open

cryptosuite lab caesar
cryptosuite lab rsa
cryptosuite lab frequency
```

E também:

```bash
python main.py
```

para acessar o menu interativo.

O resultado final deverá constituir uma aplicação completa de criptografia para **Windows e Linux**, adequada tanto para operações criptográficas práticas quanto para estudo avançado de Cryptography.

---

# INSTRUÇÃO INICIAL

Comece SOMENTE pela **FASE 1 — FOUNDATION**.

Antes de escrever código, apresente resumidamente:

1. arquitetura final;
2. bibliotecas escolhidas e motivo;
3. decisões de segurança;
4. estrutura de diretórios;
5. estratégia para compatibilidade Windows/Linux.

Depois implemente integralmente a Fase 1, instale/verifique as dependências disponíveis, execute os testes e apresente os resultados.

NÃO avance para a Fase 2 sem autorização.
