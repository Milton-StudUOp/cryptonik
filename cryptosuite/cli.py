"""Command-line interface for Cryptonik."""

from __future__ import annotations

import argparse
import base64
import getpass
import json
import sys
import time
from collections.abc import Sequence
from dataclasses import asdict
from pathlib import Path

from cryptography.hazmat.primitives import serialization

from cryptosuite import __version__
from cryptosuite.certificates import (
    generate_csr,
    generate_self_signed,
    inspect_certificate,
    load_certificate,
    validate_certificate,
)
from cryptosuite.config import (
    AppConfig,
    config_path,
    load_config,
    save_config,
    update_config,
)
from cryptosuite.core.analyzer import AnalysisResult, analyze_bytes, analyze_text
from cryptosuite.core.benchmark import run_benchmark
from cryptosuite.core.encoding import Encoding, decode, encode
from cryptosuite.core.hashing import HashAlgorithm, compare_hashes
from cryptosuite.core.hmac_tools import HMACAlgorithm, generate_hmac, verify_hmac
from cryptosuite.core.kdf import derive_key, generate_salt
from cryptosuite.core.passwords import estimated_entropy_bits, generate_password
from cryptosuite.core.random_generator import (
    random_base64,
    random_hex,
    random_urlsafe,
    random_uuid,
)
from cryptosuite.core.symmetric import (
    EncryptedData,
    SymmetricAlgorithm,
    decrypt,
    encrypt,
)
from cryptosuite.files import (
    best_effort_secure_delete,
    decrypt_file,
    decrypt_file_for_recipient,
    encrypt_file,
    encrypt_file_for_recipients,
)
from cryptosuite.files import (
    sign_file as sign_document,
)
from cryptosuite.files import (
    verify_file as verify_document,
)
from cryptosuite.files.integrity import hash_file, verify_file_hash
from cryptosuite.files.secure_delete import SECURE_DELETE_WARNING
from cryptosuite.keys import KeyAlgorithm, KeyStore
from cryptosuite.keys.key_generator import load_private_key, load_public_key
from cryptosuite.lab import (
    affine,
    avalanche_effect,
    byte_distribution,
    caesar,
    create_rsa_demo,
    demonstrate,
    frequency_analysis,
    gcd,
    hill_2x2,
    is_prime,
    legacy_hash,
    modular_inverse,
    playfair,
    rail_fence,
    shannon_entropy,
    vigenere,
)
from cryptosuite.utils.exceptions import CryptoSuiteError, ValidationError
from cryptosuite.utils.logging_config import log_operation
from cryptosuite.utils.secure_io import atomic_write_bytes
from cryptosuite.vault import Vault

MENU_ITEMS = (
    "Encrypt / Decrypt",
    "File Encryption",
    "Hashing",
    "HMAC",
    "Digital Signatures",
    "Public-Key Cryptography",
    "Key Management",
    "Password & KDF Tools",
    "Random Generator",
    "Encoding / Decoding",
    "Integrity Checker",
    "Certificates",
    "Secure Vault",
    "Crypto Lab",
    "Benchmark",
    "Settings",
    "Cryptographic Analyzer",
)


def build_parser() -> argparse.ArgumentParser:
    """Build the Cryptonik command parser."""
    parser = argparse.ArgumentParser(
        prog="cryptonik",
        description="Local cryptography and security toolkit.",
    )
    parser.add_argument("--version", action="version", version=__version__)
    subparsers = parser.add_subparsers(dest="command")
    config = subparsers.add_parser("config", help="View or change preferences.")
    config_commands = config.add_subparsers(dest="config_command", required=True)
    config_commands.add_parser("show", help="Show the effective configuration.")
    setter = config_commands.add_parser("set", help="Set a preference.")
    setter.add_argument(
        "key", choices=("logging_enabled", "debug", "log_level")
    )
    setter.add_argument("value")

    encrypt_parser = subparsers.add_parser("encrypt", help="Encrypt a file to CRYPTX.")
    encrypt_parser.add_argument("file", type=Path)
    encrypt_parser.add_argument("--output", type=Path)
    encrypt_parser.add_argument("--algorithm", choices=[item.value for item in SymmetricAlgorithm], default=SymmetricAlgorithm.XCHACHA20_POLY1305.value)
    encrypt_parser.add_argument("--force", action="store_true")

    decrypt_parser = subparsers.add_parser("decrypt", help="Decrypt a CRYPTX file.")
    decrypt_parser.add_argument("file", type=Path)
    decrypt_parser.add_argument("--output", type=Path)
    decrypt_parser.add_argument("--force", action="store_true")

    delete_parser = subparsers.add_parser(
        "secure-delete", help="Best-effort overwrite and deletion with limitations."
    )
    delete_parser.add_argument("file", type=Path)
    delete_parser.add_argument("--passes", type=int, default=1)
    delete_parser.add_argument("--yes", action="store_true")

    hash_parser = subparsers.add_parser("hash", help="Calculate a file hash.")
    hash_parser.add_argument("file", type=Path)
    hash_parser.add_argument("--algorithm", choices=[item.value for item in HashAlgorithm], default="sha256")
    compare_parser = subparsers.add_parser("compare-hashes", help="Compare two hexadecimal hashes.")
    compare_parser.add_argument("first")
    compare_parser.add_argument("second")

    integrity = subparsers.add_parser("integrity", help="Compare a file checksum.")
    integrity.add_argument("file", type=Path)
    integrity.add_argument("expected")
    integrity.add_argument("--algorithm", choices=[item.value for item in HashAlgorithm], default="sha256")

    random_parser = subparsers.add_parser("random", help="Generate random hexadecimal bytes.")
    random_parser.add_argument("--bytes", type=int, default=32, dest="byte_count")
    random_parser.add_argument(
        "--format", choices=("hex", "base64", "urlsafe", "uuid"), default="hex"
    )

    password_parser = subparsers.add_parser("password", help="Generate a secure password.")
    password_parser.add_argument("--length", type=int, default=32)
    password_parser.add_argument("--no-uppercase", action="store_true")
    password_parser.add_argument("--no-lowercase", action="store_true")
    password_parser.add_argument("--no-numbers", action="store_true")
    password_parser.add_argument("--no-symbols", action="store_true")

    public_parser = subparsers.add_parser(
        "public-key", help="Stream-encrypt or decrypt a multi-recipient file."
    )
    public_commands = public_parser.add_subparsers(dest="public_command", required=True)
    public_encrypt = public_commands.add_parser("encrypt")
    public_encrypt.add_argument("file", type=Path)
    public_encrypt.add_argument("--recipient", type=Path, action="append", required=True)
    public_encrypt.add_argument("--output", type=Path)
    public_encrypt.add_argument("--force", action="store_true")
    public_decrypt = public_commands.add_parser("decrypt")
    public_decrypt.add_argument("file", type=Path)
    public_decrypt.add_argument("--key", type=Path, required=True)
    public_decrypt.add_argument("--output", type=Path)
    public_decrypt.add_argument("--force", action="store_true")

    hmac_parser = subparsers.add_parser("hmac", help="Generate or verify an HMAC.")
    hmac_parser.add_argument("action", choices=("generate", "verify"))
    hmac_parser.add_argument("text")
    hmac_parser.add_argument("--tag")
    hmac_parser.add_argument("--algorithm", choices=[item.value for item in HMACAlgorithm], default="sha256")

    codec = subparsers.add_parser("encoding", help="Encode or decode; this is not encryption.")
    codec.add_argument("action", choices=("encode", "decode"))
    codec.add_argument("format", choices=[item.value for item in Encoding])
    codec.add_argument("value")

    keys = subparsers.add_parser("keys", help="Manage protected keys.")
    key_commands = keys.add_subparsers(dest="keys_command", required=True)
    key_generate = key_commands.add_parser("generate", help="Generate a protected key.")
    key_generate.add_argument("--type", choices=[item.value for item in KeyAlgorithm], required=True)
    key_generate.add_argument("--name", required=True)
    key_generate.add_argument("--purpose", choices=("signing", "key-exchange", "encryption"), required=True)
    key_list = key_commands.add_parser("list", help="List stored keys.")
    key_list.set_defaults(keys_command="list")
    key_info = key_commands.add_parser("info", help="Show key metadata.")
    key_info.add_argument("id")
    key_public = key_commands.add_parser("show-public", help="Show or export a public key.")
    key_public.add_argument("id")
    key_public.add_argument("--output", type=Path)
    key_import = key_commands.add_parser("import", help="Import an encrypted private key.")
    key_import.add_argument("file", type=Path)
    key_import.add_argument("--name", required=True)
    key_import.add_argument("--purpose", choices=("signing", "key-exchange", "encryption"), required=True)
    key_import_public = key_commands.add_parser(
        "import-public", help="Import a public-only key."
    )
    key_import_public.add_argument("file", type=Path)
    key_import_public.add_argument("--name", required=True)
    key_import_public.add_argument(
        "--purpose",
        choices=("signing", "key-exchange", "encryption"),
        required=True,
    )
    key_export_private = key_commands.add_parser(
        "export-private", help="Explicitly export an encrypted private key."
    )
    key_export_private.add_argument("id")
    key_export_private.add_argument("output", type=Path)
    key_backup = key_commands.add_parser("backup", help="Back up an encrypted private key.")
    key_backup.add_argument("id")
    key_backup.add_argument("destination", type=Path)
    key_change = key_commands.add_parser("change-password", help="Change private-key protection.")
    key_change.add_argument("id")
    key_delete = key_commands.add_parser("delete", help="Delete a stored key.")
    key_delete.add_argument("id")
    key_delete.add_argument("--yes", action="store_true")

    sign_parser = subparsers.add_parser("sign", help="Create a detached signature.")
    sign_parser.add_argument("file", type=Path)
    sign_parser.add_argument("--key", type=Path, required=True)
    sign_parser.add_argument("--output", type=Path)

    verify_parser = subparsers.add_parser("verify", help="Verify a detached signature.")
    verify_parser.add_argument("file", type=Path)
    verify_parser.add_argument("signature", type=Path)
    verify_parser.add_argument("--key", type=Path, required=True)

    certificate = subparsers.add_parser("certificate", help="Inspect X.509 certificates.")
    certificate_commands = certificate.add_subparsers(dest="certificate_command", required=True)
    inspect = certificate_commands.add_parser("inspect")
    inspect.add_argument("file", type=Path)
    certificate_validate = certificate_commands.add_parser("validate")
    certificate_validate.add_argument("file", type=Path)
    certificate_validate.add_argument("--ca", type=Path, action="append", required=True)
    certificate_validate.add_argument("--intermediate", type=Path, action="append", default=[])
    certificate_validate.add_argument("--hostname")
    certificate_csr = certificate_commands.add_parser("csr")
    certificate_csr.add_argument("--key", type=Path, required=True)
    certificate_csr.add_argument("--common-name", required=True)
    certificate_csr.add_argument("--san", action="append", default=[])
    certificate_csr.add_argument("--output", type=Path, required=True)
    certificate_self = certificate_commands.add_parser("self-signed")
    certificate_self.add_argument("--key", type=Path, required=True)
    certificate_self.add_argument("--common-name", required=True)
    certificate_self.add_argument("--san", action="append", default=[])
    certificate_self.add_argument("--days", type=int, default=365)
    certificate_self.add_argument("--output", type=Path, required=True)

    vault_parser = subparsers.add_parser("vault", help="Manage an encrypted vault.")
    vault_commands = vault_parser.add_subparsers(dest="vault_command", required=True)
    for command in ("create", "list", "open"):
        item = vault_commands.add_parser(command)
        item.add_argument("file", type=Path)
    vault_add = vault_commands.add_parser("add")
    vault_add.add_argument("file", type=Path)
    vault_add.add_argument("--kind", choices=("note", "password", "api-key", "token", "key", "small-file"), required=True)
    vault_add.add_argument("--name", required=True)
    vault_show = vault_commands.add_parser("show")
    vault_show.add_argument("file", type=Path)
    vault_show.add_argument("id")
    vault_delete = vault_commands.add_parser("delete")
    vault_delete.add_argument("file", type=Path)
    vault_delete.add_argument("id")
    vault_add_file = vault_commands.add_parser("add-file")
    vault_add_file.add_argument("file", type=Path)
    vault_add_file.add_argument("input", type=Path)
    vault_add_file.add_argument("--name")
    vault_extract = vault_commands.add_parser("extract")
    vault_extract.add_argument("file", type=Path)
    vault_extract.add_argument("id")
    vault_extract.add_argument("output", type=Path)
    vault_backup = vault_commands.add_parser("backup")
    vault_backup.add_argument("file", type=Path)
    vault_backup.add_argument("output", type=Path)
    vault_change = vault_commands.add_parser("change-password")
    vault_change.add_argument("file", type=Path)

    lab_parser = subparsers.add_parser("lab", help="Run insecure educational demonstrations.")
    lab_commands = lab_parser.add_subparsers(dest="lab_command", required=True)
    lab_caesar = lab_commands.add_parser("caesar")
    lab_caesar.add_argument("text")
    lab_caesar.add_argument("--shift", type=int, required=True)
    lab_frequency = lab_commands.add_parser("frequency")
    lab_frequency.add_argument("text")
    lab_frequency.add_argument("--ngram", type=int, choices=(1, 2, 3), default=1)
    lab_rsa = lab_commands.add_parser("rsa")
    lab_rsa.add_argument("--p", type=int, required=True)
    lab_rsa.add_argument("--q", type=int, required=True)
    lab_rsa.add_argument("--e", type=int, default=65537)
    for name in ("vigenere", "playfair"):
        item = lab_commands.add_parser(name)
        item.add_argument("text")
        item.add_argument("--key", required=True)
        item.add_argument("--decrypt", action="store_true")
    lab_affine = lab_commands.add_parser("affine")
    lab_affine.add_argument("text")
    lab_affine.add_argument("--a", type=int, required=True)
    lab_affine.add_argument("--b", type=int, required=True)
    lab_affine.add_argument("--decrypt", action="store_true")
    lab_rail = lab_commands.add_parser("rail-fence")
    lab_rail.add_argument("text")
    lab_rail.add_argument("--rails", type=int, required=True)
    lab_rail.add_argument("--decrypt", action="store_true")
    lab_hill = lab_commands.add_parser("hill")
    lab_hill.add_argument("text")
    lab_hill.add_argument("--matrix", nargs=4, type=int, required=True)
    lab_hill.add_argument("--decrypt", action="store_true")
    lab_dh = lab_commands.add_parser("diffie-hellman")
    lab_dh.add_argument("--p", type=int, required=True)
    lab_dh.add_argument("--g", type=int, required=True)
    lab_dh.add_argument("--alice", type=int, required=True)
    lab_dh.add_argument("--bob", type=int, required=True)
    lab_entropy = lab_commands.add_parser("entropy")
    lab_entropy.add_argument("file", type=Path)
    lab_avalanche = lab_commands.add_parser("avalanche")
    lab_avalanche.add_argument("first")
    lab_avalanche.add_argument("second")
    lab_legacy = lab_commands.add_parser("legacy-hash")
    lab_legacy.add_argument("algorithm", choices=("md5", "sha1"))
    lab_legacy.add_argument("text")
    lab_number = lab_commands.add_parser("number-theory")
    lab_number.add_argument("operation", choices=("gcd", "inverse", "prime"))
    lab_number.add_argument("first", type=int)
    lab_number.add_argument("second", type=int, nargs="?")

    subparsers.add_parser("benchmark", help="Benchmark algorithms locally.")
    analyzer = subparsers.add_parser(
        "analyze", help="Identify an encoding, container, or encrypted-looking value."
    )
    analyzer.add_argument("value", nargs="?", help="Text or encoded value to inspect.")
    analyzer.add_argument("--file", type=Path, help="Read the value or bytes from a file.")
    return parser


def run_cli(argv: Sequence[str] | None, config: AppConfig) -> int:
    """Run one CLI session and log only its non-secret operation name/status."""
    raw_arguments = list(argv) if argv is not None else sys.argv[1:]
    operation = _safe_operation_name(raw_arguments)
    try:
        result = _dispatch_cli(argv, config)
        log_operation(operation, "N/A", "Success" if result == 0 else "Failed")
        return result
    except Exception:
        log_operation(operation, "N/A", "Failed")
        raise


def _dispatch_cli(argv: Sequence[str] | None, config: AppConfig) -> int:
    """Parse arguments or open the interactive menu."""
    args = build_parser().parse_args(argv)
    if args.command == "config":
        return _handle_config(args, config)
    if args.command == "encrypt":
        password = _confirmed_password()
        output = encrypt_file(args.file, password, args.output, algorithm=SymmetricAlgorithm(args.algorithm), overwrite=args.force)
        print(f"Encrypted: {output}")
        return 0
    if args.command == "decrypt":
        output = decrypt_file(args.file, getpass.getpass("Password: "), args.output, overwrite=args.force)
        print(f"Decrypted: {output}")
        return 0
    if args.command == "secure-delete":
        print("WARNING: " + SECURE_DELETE_WARNING)
        confirmed = args.yes or input(f"Delete {args.file}? [y/N]: ").strip().casefold() in {"y", "yes"}
        if not confirmed:
            raise ValidationError("Deletion cancelled.")
        best_effort_secure_delete(args.file, passes=args.passes)
        print(f"Deleted: {args.file}")
        return 0
    if args.command == "hash":
        print(hash_file(args.file, HashAlgorithm(args.algorithm)))
        return 0
    if args.command == "compare-hashes":
        matched = compare_hashes(args.first, args.second)
        print("MATCH" if matched else "MISMATCH")
        return 0 if matched else 1
    if args.command == "integrity":
        matched = verify_file_hash(
            args.file,
            _checksum_value(args.expected),
            HashAlgorithm(args.algorithm),
        )
        print("MATCH" if matched else "MISMATCH")
        return 0 if matched else 1
    if args.command == "random":
        generators = {
            "hex": random_hex,
            "base64": random_base64,
            "urlsafe": random_urlsafe,
        }
        print(
            random_uuid()
            if args.format == "uuid"
            else generators[args.format](args.byte_count)
        )
        return 0
    if args.command == "password":
        print(
            generate_password(
                args.length,
                uppercase=not args.no_uppercase,
                lowercase=not args.no_lowercase,
                numbers=not args.no_numbers,
                symbols=not args.no_symbols,
            )
        )
        return 0
    if args.command == "public-key":
        if args.public_command == "encrypt":
            recipients = [
                load_public_key(path.read_bytes()) for path in args.recipient
            ]
            output = encrypt_file_for_recipients(
                args.file,
                recipients,
                args.output,
                overwrite=args.force,
                progress=_progress_reporter(),
            )
            print(f"\nEncrypted: {output}")
            return 0
        private = load_private_key(
            args.key.read_bytes(), getpass.getpass("Key password: ")
        )
        output = decrypt_file_for_recipient(
            args.file,
            private,
            args.output,
            overwrite=args.force,
            progress=_progress_reporter(),
        )
        print(f"\nDecrypted: {output}")
        return 0
    if args.command == "hmac":
        return _handle_hmac(args)
    if args.command == "encoding":
        selected = Encoding(args.format)
        result = encode(args.value.encode(), selected) if args.action == "encode" else decode(args.value, selected).decode()
        print(result)
        return 0
    if args.command == "keys":
        return _handle_keys(args)
    if args.command == "sign":
        private = load_private_key(args.key.read_bytes(), getpass.getpass("Key password: "))
        output = args.output or Path(f"{args.file}.sig")
        if output.exists():
            raise ValidationError(f"Signature already exists: {output}")
        sign_document(args.file, private, output)
        print(f"Signature: {output}")
        return 0
    if args.command == "verify":
        valid = verify_document(
            args.file,
            args.signature,
            load_public_key(args.key.read_bytes()),
        )
        print("VALID" if valid else "INVALID")
        return 0 if valid else 1
    if args.command == "certificate":
        return _handle_certificate(args)
    if args.command == "vault":
        return _handle_vault(args)
    if args.command == "lab":
        return _handle_lab(args)
    if args.command == "benchmark":
        for result in run_benchmark():
            print(f"{result.algorithm:24} {result.mebibytes_per_second:10.2f} MiB/s")
        return 0
    if args.command == "analyze":
        if args.file is not None and args.value is not None:
            raise ValidationError("Use either a value or --file, not both.")
        if args.file is not None:
            result = analyze_bytes(args.file.read_bytes())
        elif args.value is not None:
            result = analyze_text(args.value)
        else:
            raise ValidationError("Provide a value or --file.")
        _print_analysis(result)
        return 0
    return interactive_menu()


def _safe_operation_name(arguments: list[str]) -> str:
    """Return an allow-listed operation label without recording argument values."""
    allowed = {
        "analyze",
        "benchmark",
        "certificate",
        "config",
        "compare-hashes",
        "decrypt",
        "encoding",
        "encrypt",
        "hash",
        "hmac",
        "integrity",
        "keys",
        "lab",
        "password",
        "public-key",
        "random",
        "secure-delete",
        "sign",
        "vault",
        "verify",
    }
    return arguments[0].title() if arguments and arguments[0] in allowed else "Interactive"


def _key_store() -> KeyStore:
    return KeyStore(config_path().parent / "keys")


def _handle_keys(args: argparse.Namespace) -> int:
    store = _key_store()
    if args.keys_command == "list":
        for record in store.list():
            print(f"{record.id}  {record.algorithm:10} {record.purpose:12} {record.name}")
        return 0
    if args.keys_command == "info":
        print(json.dumps(asdict(store.info(args.id)), indent=2))
        return 0
    if args.keys_command == "show-public":
        data = store.export_public(args.id)
        if args.output:
            atomic_write_bytes(args.output, data, mode=0o644)
            print(f"Public key exported: {args.output}")
        else:
            print(data.decode("ascii"), end="")
        return 0
    if args.keys_command == "import":
        current = getpass.getpass("Current key password: ")
        storage = _confirmed_password("New storage password: ", "Confirm password: ")
        record = store.import_private(
            args.name,
            args.purpose,
            args.file.read_bytes(),
            current,
            storage,
        )
        print(f"Imported key {record.id}\nFingerprint: {record.fingerprint}")
        return 0
    if args.keys_command == "import-public":
        record = store.import_public(
            args.name, args.purpose, args.file.read_bytes()
        )
        print(f"Imported public key {record.id}\nFingerprint: {record.fingerprint}")
        return 0
    if args.keys_command == "export-private":
        atomic_write_bytes(
            args.output, store.export_private(args.id), mode=0o600
        )
        print(f"Encrypted private key exported: {args.output}")
        return 0
    if args.keys_command == "backup":
        print(f"Backup created: {store.backup(args.id, args.destination)}")
        return 0
    if args.keys_command == "change-password":
        old = getpass.getpass("Current password: ")
        new = _confirmed_password("New password: ", "Confirm password: ")
        store.change_password(args.id, old, new)
        print("Key protection password changed.")
        return 0
    if args.keys_command == "delete":
        confirmed = args.yes or input(f"Delete key {args.id} permanently? [y/N]: ").strip().casefold() in {"y", "yes"}
        if not confirmed:
            raise ValidationError("Key deletion cancelled.")
        store.delete(args.id)
        print(f"Deleted key: {args.id}")
        return 0
    password = _confirmed_password("Key protection password: ", "Confirm password: ")
    record = store.generate(args.name, KeyAlgorithm(args.type), args.purpose, password)
    print(f"Generated key {record.id}\nFingerprint: {record.fingerprint}")
    return 0


def _confirmed_password(prompt: str = "Password: ", confirmation: str = "Confirm password: ") -> str:
    password = getpass.getpass(prompt)
    if password != getpass.getpass(confirmation):
        raise ValidationError("Passwords do not match.")
    if not password:
        raise ValidationError("Password must not be empty.")
    return password


def _handle_hmac(args: argparse.Namespace) -> int:
    key = getpass.getpass("HMAC key: ").encode()
    algorithm = HMACAlgorithm(args.algorithm)
    if args.action == "generate":
        print(generate_hmac(key, args.text.encode(), algorithm).hex())
        return 0
    if not args.tag:
        raise ValidationError("--tag is required for HMAC verification.")
    try:
        tag = bytes.fromhex(args.tag)
    except ValueError as exc:
        raise ValidationError("HMAC tag must be hexadecimal.") from exc
    valid = verify_hmac(key, args.text.encode(), tag, algorithm)
    print("VALID" if valid else "INVALID")
    return 0 if valid else 1


def _handle_vault(args: argparse.Namespace) -> int:
    password = getpass.getpass("Master password: ")
    if args.vault_command == "create":
        if args.file.exists():
            raise ValidationError(f"Vault already exists: {args.file}")
        Vault.create(args.file, password)
        print(f"Created vault: {args.file}")
        return 0
    vault = Vault.open(args.file, password)
    if args.vault_command in {"list", "open"}:
        for entry in vault.list_entries():
            print(f"{entry.id}  {entry.kind:10} {entry.name}")
        return 0
    if args.vault_command == "show":
        entry = vault.get(args.id)
        if entry.kind == "small-file":
            raise ValidationError("Use vault extract to retrieve a file entry.")
        print(f"Name: {entry.name}\nKind: {entry.kind}\nValue: {entry.value}")
        return 0
    if args.vault_command == "delete":
        if not vault.delete(args.id):
            raise ValidationError(f"Unknown vault entry: {args.id}")
        vault.save()
        print(f"Deleted vault entry: {args.id}")
        return 0
    if args.vault_command == "add-file":
        entry = vault.add_file(args.input, args.name)
        vault.save()
        print(f"Added vault file entry: {entry.id}")
        return 0
    if args.vault_command == "extract":
        print(f"Extracted: {vault.extract_file(args.id, args.output)}")
        return 0
    if args.vault_command == "backup":
        print(f"Backup created: {vault.backup(args.output)}")
        return 0
    if args.vault_command == "change-password":
        new_password = _confirmed_password("New master password: ", "Confirm password: ")
        vault.change_master_password(new_password)
        print("Master password changed.")
        return 0
    entry = vault.add(args.kind, args.name, getpass.getpass("Secret value: "))
    vault.save()
    print(f"Added vault entry: {entry.id}")
    return 0


def _handle_lab(args: argparse.Namespace) -> int:
    print("EDUCATIONAL IMPLEMENTATION — NOT FOR PRODUCTION USE")
    if args.lab_command == "caesar":
        print(caesar(args.text, args.shift))
    elif args.lab_command == "frequency":
        for value, count, ratio in frequency_analysis(args.text, args.ngram):
            print(f"{value}: {count} ({ratio:.2%})")
    elif args.lab_command == "rsa":
        print(asdict(create_rsa_demo(args.p, args.q, args.e)))
    elif args.lab_command == "vigenere":
        print(vigenere(args.text, args.key, decrypt=args.decrypt))
    elif args.lab_command == "playfair":
        print(playfair(args.text, args.key, decrypt=args.decrypt))
    elif args.lab_command == "affine":
        print(affine(args.text, args.a, args.b, decrypt=args.decrypt))
    elif args.lab_command == "rail-fence":
        print(rail_fence(args.text, args.rails, decrypt=args.decrypt))
    elif args.lab_command == "hill":
        matrix = ((args.matrix[0], args.matrix[1]), (args.matrix[2], args.matrix[3]))
        print(hill_2x2(args.text, matrix, decrypt=args.decrypt))
    elif args.lab_command == "diffie-hellman":
        result = demonstrate(args.p, args.g, args.alice, args.bob)
        print(json.dumps(asdict(result), indent=2))
        print("WARNING: unauthenticated Diffie-Hellman is vulnerable to MITM.")
    elif args.lab_command == "entropy":
        data = args.file.read_bytes()
        print(f"File size: {len(data)} bytes")
        print(f"Shannon entropy: {shannon_entropy(data):.6f} bits/byte")
        print("Most frequent bytes:")
        distribution = byte_distribution(data)
        for value, count in sorted(
            enumerate(distribution), key=lambda item: item[1], reverse=True
        )[:10]:
            if count:
                print(f"  0x{value:02X}: {count}")
        print("High entropy does not prove that data is encrypted.")
    elif args.lab_command == "avalanche":
        changed, total, percentage = avalanche_effect(
            args.first.encode(), args.second.encode()
        )
        print(f"Changed bits: {changed} / {total}\nDifference: {percentage:.2f}%")
    elif args.lab_command == "legacy-hash":
        print("WARNING: MD5 and SHA-1 are cryptographically broken for security use.")
        print("Do not use them for passwords, signatures, certificates, or verification.")
        print(legacy_hash(args.text.encode(), args.algorithm))
    elif args.operation == "prime":
        print("PRIME" if is_prime(args.first) else "COMPOSITE")
    elif args.operation == "gcd":
        if args.second is None:
            raise ValidationError("gcd requires two integers.")
        print(gcd(args.first, args.second))
    else:
        if args.second is None:
            raise ValidationError("inverse requires a modulus.")
        print(modular_inverse(args.first, args.second))
    return 0


def _handle_certificate(args: argparse.Namespace) -> int:
    if args.certificate_command == "inspect":
        info = inspect_certificate(load_certificate(args.file.read_bytes()))
        print(json.dumps(asdict(info), indent=2))
        return 0
    if args.certificate_command == "validate":
        result = validate_certificate(
            load_certificate(args.file.read_bytes()),
            [load_certificate(path.read_bytes()) for path in args.intermediate],
            [load_certificate(path.read_bytes()) for path in args.ca],
            hostname=args.hostname,
        )
        print("VALID" if result.valid else "INVALID")
        for error in result.errors:
            print(f"- {error}")
        return 0 if result.valid else 1
    private = load_private_key(
        args.key.read_bytes(), getpass.getpass("Key password: ")
    )
    if args.certificate_command == "csr":
        data = generate_csr(private, args.common_name, args.san).public_bytes(
            serialization.Encoding.PEM
        )
    else:
        data = generate_self_signed(
            private,
            args.common_name,
            days_valid=args.days,
            san_names=args.san,
        ).public_bytes(serialization.Encoding.PEM)
    atomic_write_bytes(args.output, data, mode=0o644)
    print(f"Created: {args.output}")
    return 0


def _handle_config(args: argparse.Namespace, config: AppConfig) -> int:
    if args.config_command == "show":
        print(json.dumps(asdict(config), indent=2, sort_keys=True))
        print(f"Configuration file: {config_path()}")
        return 0
    updated = update_config(config, args.key, args.value)
    target = save_config(updated)
    print(f"Updated {args.key}. Configuration saved to {target}")
    return 0


def interactive_menu() -> int:
    """Display the fully interactive menu until the user exits."""
    while True:
        print("=" * 50)
        print("                  CRYPTONIK")
        print("          Cryptography & Security Toolkit")
        print("=" * 50)
        print()
        for number, label in enumerate(MENU_ITEMS, start=1):
            print(f"[{number}] {label}")
        print("[0] Exit")
        try:
            choice = input("\nSelect an option: ").strip()
        except EOFError:
            print()
            return 0
        if choice == "0":
            print("Goodbye.")
            return 0
        if choice.isdigit() and 1 <= int(choice) <= len(MENU_ITEMS):
            try:
                _INTERACTIVE_HANDLERS[int(choice)]()
            except CryptoSuiteError as exc:
                print(f"\nERROR\n\n{exc}\n")
            except ValueError:
                print("\nERROR\n\nInvalid numeric or encoded input.\n")
            except OSError:
                print("\nERROR\n\nUnable to access the requested file.\n")
            except (EOFError, KeyboardInterrupt):
                print("\nOperation cancelled.\n")
        else:
            print("\nInvalid selection. Enter a number shown in the menu.\n")


def _interactive_text_crypto() -> None:
    print("\nTEXT ENCRYPTION\n[1] Encrypt\n[2] Decrypt\n[0] Back")
    action = input("Select an option: ").strip()
    if action == "0":
        return
    password = getpass.getpass("Password: ")
    if action == "1":
        plaintext = input("Text: ").encode("utf-8")
        salt = generate_salt()
        key = derive_key(password, salt)
        sealed = encrypt(plaintext, key, SymmetricAlgorithm.XCHACHA20_POLY1305)
        token = {
            "ciphertext": _b64(sealed.ciphertext),
            "nonce": _b64(sealed.nonce),
            "salt": _b64(salt),
            "version": 1,
        }
        print("\nEncrypted token:\n" + base64.urlsafe_b64encode(json.dumps(token).encode()).decode())
    elif action == "2":
        token_text = input("Encrypted token: ").strip()
        try:
            token = json.loads(base64.urlsafe_b64decode(token_text).decode())
            if token.get("version") != 1:
                raise ValueError
            key = derive_key(password, _unb64(token["salt"]))
            plaintext = decrypt(
                EncryptedData(
                    SymmetricAlgorithm.XCHACHA20_POLY1305,
                    _unb64(token["nonce"]),
                    _unb64(token["ciphertext"]),
                ),
                key,
            )
            print("\nDecrypted text:\n" + plaintext.decode("utf-8"))
        except (ValueError, KeyError, UnicodeError, json.JSONDecodeError) as exc:
            raise ValidationError("Invalid encrypted text token.") from exc
    else:
        raise ValidationError("Invalid selection.")


def _interactive_file_crypto() -> None:
    print("\nFILE ENCRYPTION\n[1] Encrypt\n[2] Decrypt\n[3] Best-effort secure delete\n[0] Back")
    action = input("Select an option: ").strip()
    if action == "0":
        return
    source = Path(input("Input file: ").strip().strip('"'))
    if action == "3":
        print("WARNING: " + SECURE_DELETE_WARNING)
        if input(f"Delete {source}? [y/N]: ").strip().casefold() not in {"y", "yes"}:
            raise ValidationError("Deletion cancelled.")
        passes = int(input("Overwrite passes [1]: ").strip() or "1")
        best_effort_secure_delete(source, passes=passes)
        print(f"\nDeleted: {source}\n")
        return
    output_text = input("Output file (leave blank for default): ").strip().strip('"')
    output = Path(output_text) if output_text else None
    password = getpass.getpass("Password: ")
    if action == "1":
        destination = output or Path(f"{source}.cryptx")
        overwrite = _confirm_existing_destination(destination)
        print(f"Output: {destination}")
        result = encrypt_file(
            source,
            password,
            destination,
            overwrite=overwrite,
            progress=_progress_reporter(),
        )
        print(f"\nEncrypted: {result}\n")
    elif action == "2":
        destination = output or _default_decrypted_path(source)
        overwrite = _confirm_existing_destination(destination)
        print(f"Output: {destination}")
        result = decrypt_file(
            source,
            password,
            destination,
            overwrite=overwrite,
            progress=_progress_reporter(),
        )
        print(f"\nDecrypted: {result}\n")
    else:
        raise ValidationError("Invalid selection.")


def _interactive_hashing() -> None:
    print("\nHASHING\n[1] Hash file\n[2] Compare two hashes\n[0] Back")
    action = input("Select an option: ").strip()
    if action == "0":
        return
    if action == "2":
        first = input("First hash: ")
        second = input("Second hash: ")
        print("\nMATCH\n" if compare_hashes(first, second) else "\nMISMATCH\n")
        return
    if action != "1":
        raise ValidationError("Invalid selection.")
    path = Path(input("\nFile to hash: ").strip().strip('"'))
    algorithm = _select_enum("Hash algorithm", HashAlgorithm)
    print(f"\n{algorithm.value.upper()}:\n{hash_file(path, algorithm)}\n")


def _interactive_hmac() -> None:
    print("\nHMAC\n[1] Generate\n[2] Verify\n[0] Back")
    action = input("Select an option: ").strip()
    if action == "0":
        return
    text = input("Text: ").encode()
    key = getpass.getpass("HMAC key: ").encode()
    algorithm = _select_enum("Algorithm", HMACAlgorithm)
    if action == "1":
        print("\nHMAC:\n" + generate_hmac(key, text, algorithm).hex() + "\n")
    elif action == "2":
        try:
            tag = bytes.fromhex(input("Expected HMAC: ").strip())
        except ValueError as exc:
            raise ValidationError("HMAC must be hexadecimal.") from exc
        print("\nVALID\n" if verify_hmac(key, text, tag, algorithm) else "\nINVALID\n")
    else:
        raise ValidationError("Invalid selection.")


def _interactive_signatures() -> None:
    print("\nDIGITAL SIGNATURES\n[1] Sign file\n[2] Verify file\n[0] Back")
    action = input("Select an option: ").strip()
    if action == "0":
        return
    document = Path(input("Document: ").strip().strip('"'))
    if action == "1":
        key_path = Path(input("Encrypted private key: ").strip().strip('"'))
        output_text = input("Signature output (blank for .sig): ").strip().strip('"')
        output = Path(output_text) if output_text else Path(f"{document}.sig")
        if output.exists():
            raise ValidationError(f"Signature already exists: {output}")
        private = load_private_key(key_path.read_bytes(), getpass.getpass("Key password: "))
        sign_document(document, private, output)
        print(f"\nSignature created: {output}\n")
    elif action == "2":
        signature = Path(input("Signature file: ").strip().strip('"'))
        key_path = Path(input("Public key: ").strip().strip('"'))
        valid = verify_document(
            document, signature, load_public_key(key_path.read_bytes())
        )
        print("\nVALID\n" if valid else "\nINVALID\n")
    else:
        raise ValidationError("Invalid selection.")


def _interactive_public_key() -> None:
    print("\nPUBLIC-KEY CRYPTOGRAPHY\n[1] Encrypt for recipients\n[2] Decrypt envelope\n[0] Back")
    action = input("Select an option: ").strip()
    if action == "0":
        return
    source = Path(input("Input file: ").strip().strip('"'))
    output = Path(input("Output file: ").strip().strip('"'))
    if action == "1":
        paths = [Path(item.strip().strip('"')) for item in input("Public key files (comma-separated): ").split(",")]
        keys = [load_public_key(path.read_bytes()) for path in paths]
        encrypt_file_for_recipients(source, keys, output, progress=_progress_reporter())
        print(f"\nEncrypted envelope: {output}\n")
    elif action == "2":
        key_path = Path(input("Encrypted private key: ").strip().strip('"'))
        private = load_private_key(key_path.read_bytes(), getpass.getpass("Key password: "))
        decrypt_file_for_recipient(source, private, output, progress=_progress_reporter())
        print(f"\nDecrypted: {output}\n")
    else:
        raise ValidationError("Invalid selection.")


def _interactive_keys() -> None:
    print(
        "\nKEY MANAGEMENT\n[1] Generate\n[2] List\n[3] Information"
        "\n[4] Show/export public key\n[5] Import private key\n[6] Backup"
        "\n[7] Change protection password\n[8] Delete"
        "\n[9] Import public-only key\n[10] Export encrypted private key\n[0] Back"
    )
    action = input("Select an option: ").strip()
    if action == "0":
        return
    store = _key_store()
    if action == "1":
        algorithm = _select_enum("Key type", KeyAlgorithm)
        name = input("Key name: ").strip()
        purposes = {KeyAlgorithm.ED25519: "signing", KeyAlgorithm.EC_P256: "signing", KeyAlgorithm.X25519: "key-exchange", KeyAlgorithm.RSA_3072: "encryption"}
        record = store.generate(name, algorithm, purposes[algorithm], _confirmed_password("Protection password: ", "Confirm password: "))
        print(f"\nKey ID: {record.id}\nFingerprint: {record.fingerprint}\n")
    elif action == "2":
        records = store.list()
        print()
        for record in records:
            print(
                f"{record.id}  {record.algorithm:10} "
                f"{record.purpose:12} {record.name}"
            )
        print()
    elif action == "3":
        print(json.dumps(asdict(store.info(input("Key ID: ").strip().upper())), indent=2))
    elif action == "4":
        identifier = input("Key ID: ").strip().upper()
        data = store.export_public(identifier)
        output = input("Output file (blank to display): ").strip().strip('"')
        if output:
            atomic_write_bytes(Path(output), data, mode=0o644)
            print(f"\nExported: {output}\n")
        else:
            print("\n" + data.decode("ascii"))
    elif action == "5":
        path = Path(input("Encrypted private key file: ").strip().strip('"'))
        name = input("Key name: ").strip()
        purpose = input("Purpose [signing/key-exchange/encryption]: ").strip()
        record = store.import_private(
            name,
            purpose,
            path.read_bytes(),
            getpass.getpass("Current key password: "),
            _confirmed_password("New storage password: ", "Confirm password: "),
        )
        print(f"\nImported: {record.id}\n")
    elif action == "6":
        identifier = input("Key ID: ").strip().upper()
        destination = Path(input("Backup destination: ").strip().strip('"'))
        print(f"\nBackup: {store.backup(identifier, destination)}\n")
    elif action == "7":
        identifier = input("Key ID: ").strip().upper()
        store.change_password(
            identifier,
            getpass.getpass("Current password: "),
            _confirmed_password("New password: ", "Confirm password: "),
        )
        print("\nPassword changed.\n")
    elif action == "8":
        identifier = input("Key ID: ").strip().upper()
        if input(f"Delete {identifier} permanently? [y/N]: ").strip().casefold() not in {"y", "yes"}:
            raise ValidationError("Key deletion cancelled.")
        store.delete(identifier)
        print("\nKey deleted.\n")
    elif action == "9":
        path = Path(input("Public key file: ").strip().strip('"'))
        record = store.import_public(
            input("Key name: ").strip(),
            input("Purpose [signing/key-exchange/encryption]: ").strip(),
            path.read_bytes(),
        )
        print(f"\nImported public key: {record.id}\n")
    elif action == "10":
        identifier = input("Key ID: ").strip().upper()
        destination = Path(input("Export destination: ").strip().strip('"'))
        atomic_write_bytes(
            destination, store.export_private(identifier), mode=0o600
        )
        print(f"\nExported: {destination}\n")
    else:
        raise ValidationError("Invalid selection.")


def _interactive_passwords() -> None:
    length = int(input("\nPassword length [32]: ").strip() or "32")
    uppercase = _yes_no("Include uppercase?", True)
    lowercase = _yes_no("Include lowercase?", True)
    numbers = _yes_no("Include numbers?", True)
    symbols = _yes_no("Include symbols?", True)
    password = generate_password(
        length,
        uppercase=uppercase,
        lowercase=lowercase,
        numbers=numbers,
        symbols=symbols,
    )
    print("\nGenerated password:\n" + password + "\n")
    alphabet_size = (
        (26 if uppercase else 0)
        + (26 if lowercase else 0)
        + (10 if numbers else 0)
        + (29 if symbols else 0)
    )
    estimate = estimated_entropy_bits(length, alphabet_size)
    print(f"Approximate theoretical entropy: {estimate:.1f} bits")
    print("This estimate assumes independent uniform choices; it is not proof of strength.\n")


def _interactive_random() -> None:
    print("\nRANDOM GENERATOR\n[1] Hex\n[2] Base64\n[3] URL-safe token\n[4] UUIDv4\n[0] Back")
    action = input("Select an option: ").strip()
    if action == "0":
        return
    if action == "4":
        print("\nUUIDv4:\n" + random_uuid() + "\n")
        return
    length = int(input("Number of random bytes [32]: ").strip() or "32")
    generators = {"1": random_hex, "2": random_base64, "3": random_urlsafe}
    if action not in generators:
        raise ValidationError("Invalid selection.")
    print("\nRandom value:\n" + generators[action](length) + "\n")


def _interactive_encoding() -> None:
    print("\nENCODING IS NOT ENCRYPTION\n[1] Encode\n[2] Decode\n[0] Back")
    action = input("Select an option: ").strip()
    if action == "0":
        return
    selected = _select_enum("Format", Encoding)
    value = input("Value: ")
    if action == "1":
        print("\nResult:\n" + encode(value.encode(), selected) + "\n")
    elif action == "2":
        print("\nResult:\n" + decode(value, selected).decode("utf-8") + "\n")
    else:
        raise ValidationError("Invalid selection.")


def _interactive_integrity() -> None:
    path = Path(input("\nFile: ").strip().strip('"'))
    expected = _checksum_value(input("Expected checksum or checksum file: ").strip())
    algorithm = _select_enum("Algorithm", HashAlgorithm)
    print("\nMATCH\n" if verify_file_hash(path, expected, algorithm) else "\nMISMATCH\n")


def _interactive_certificate() -> None:
    print("\nCERTIFICATES\n[1] Inspect\n[2] Validate\n[3] Generate CSR\n[4] Generate self-signed\n[0] Back")
    action = input("Select an option: ").strip()
    if action == "0":
        return
    if action == "1":
        path = Path(input("Certificate file: ").strip().strip('"'))
        info = inspect_certificate(load_certificate(path.read_bytes()))
        print("\n" + json.dumps(asdict(info), indent=2) + "\n")
    elif action == "2":
        path = Path(input("Certificate file: ").strip().strip('"'))
        roots = [
            load_certificate(Path(item.strip().strip('"')).read_bytes())
            for item in input("Trust-root files (comma-separated): ").split(",")
            if item.strip()
        ]
        hostname = input("Hostname (blank to skip): ").strip() or None
        result = validate_certificate(
            load_certificate(path.read_bytes()), trust_roots=roots, hostname=hostname
        )
        print("\nVALID" if result.valid else "\nINVALID")
        for error in result.errors:
            print(f"- {error}")
        print()
    elif action in {"3", "4"}:
        key_path = Path(input("Encrypted private key: ").strip().strip('"'))
        private = load_private_key(
            key_path.read_bytes(), getpass.getpass("Key password: ")
        )
        common_name = input("Common name: ").strip()
        names = [item.strip() for item in input("SAN DNS names (comma-separated): ").split(",") if item.strip()]
        output = Path(input("Output file: ").strip().strip('"'))
        if action == "3":
            data = generate_csr(private, common_name, names).public_bytes(
                serialization.Encoding.PEM
            )
        else:
            days = int(input("Validity days [365]: ").strip() or "365")
            data = generate_self_signed(
                private, common_name, days_valid=days, san_names=names
            ).public_bytes(serialization.Encoding.PEM)
        atomic_write_bytes(output, data, mode=0o644)
        print(f"\nCreated: {output}\n")
    else:
        raise ValidationError("Invalid selection.")


def _interactive_vault() -> None:
    print(
        "\nSECURE VAULT\n[1] Create\n[2] List entries\n[3] Add entry"
        "\n[4] Show entry\n[5] Delete entry\n[6] Add small file"
        "\n[7] Extract file\n[8] Backup\n[9] Change master password\n[0] Back"
    )
    action = input("Select an option: ").strip()
    if action == "0":
        return
    path = Path(input("Vault file: ").strip().strip('"'))
    password = getpass.getpass("Master password: ")
    if action == "1":
        Vault.create(path, password)
        print(f"\nCreated: {path}\n")
        return
    vault = Vault.open(path, password)
    if action == "2":
        print()
        for entry in vault.list_entries():
            print(f"{entry.id}  {entry.kind:10} {entry.name}")
        print()
    elif action == "3":
        kind = input("Kind [note/password/api-key/token/key/small-file]: ").strip()
        name = input("Name: ").strip()
        entry = vault.add(kind, name, getpass.getpass("Secret value: "))
        vault.save()
        print(f"\nAdded: {entry.id}\n")
    elif action == "4":
        entry = vault.get(input("Entry ID: ").strip())
        if entry.kind == "small-file":
            raise ValidationError("Use Extract file for small-file entries.")
        print(f"\nName: {entry.name}\nKind: {entry.kind}\nValue: {entry.value}\n")
    elif action == "5":
        identifier = input("Entry ID: ").strip()
        if not vault.delete(identifier):
            raise ValidationError(f"Unknown vault entry: {identifier}")
        vault.save()
        print("\nEntry deleted.\n")
    elif action == "6":
        source = Path(input("Input file: ").strip().strip('"'))
        entry = vault.add_file(source, input("Entry name (blank for filename): ").strip() or None)
        vault.save()
        print(f"\nAdded file: {entry.id}\n")
    elif action == "7":
        identifier = input("Entry ID: ").strip()
        destination = Path(input("Output file: ").strip().strip('"'))
        print(f"\nExtracted: {vault.extract_file(identifier, destination)}\n")
    elif action == "8":
        destination = Path(input("Backup destination: ").strip().strip('"'))
        print(f"\nBackup: {vault.backup(destination)}\n")
    elif action == "9":
        vault.change_master_password(
            _confirmed_password("New master password: ", "Confirm password: ")
        )
        print("\nMaster password changed.\n")
    else:
        raise ValidationError("Invalid selection.")


def _interactive_lab() -> None:
    print(
        "\nEDUCATIONAL IMPLEMENTATIONS — NOT FOR PRODUCTION USE"
        "\n[1] Caesar\n[2] Vigenere\n[3] Affine\n[4] Rail Fence"
        "\n[5] Playfair\n[6] Hill 2x2\n[7] Frequency analysis"
        "\n[8] Entropy\n[9] Avalanche effect\n[10] RSA demo"
        "\n[11] Diffie-Hellman demo\n[12] Legacy MD5/SHA-1"
        "\n[13] Number theory\n[0] Back"
    )
    action = input("Select an option: ").strip()
    if action == "0":
        return
    if action == "1":
        print("\n" + caesar(input("Text: "), int(input("Shift: "))) + "\n")
    elif action == "2":
        print("\n" + vigenere(input("Text: "), input("Key: ")) + "\n")
    elif action == "3":
        print("\n" + affine(input("Text: "), int(input("a: ")), int(input("b: "))) + "\n")
    elif action == "4":
        print("\n" + rail_fence(input("Text: "), int(input("Rails: "))) + "\n")
    elif action == "5":
        print("\n" + playfair(input("Text: "), input("Key: ")) + "\n")
    elif action == "6":
        values = [int(item) for item in input("Matrix a b c d: ").split()]
        if len(values) != 4:
            raise ValidationError("Hill matrix requires four integers.")
        matrix = ((values[0], values[1]), (values[2], values[3]))
        print("\n" + hill_2x2(input("Text: "), matrix) + "\n")
    elif action == "7":
        for value, count, ratio in frequency_analysis(input("Text: "), int(input("N-gram [1-3]: ") or "1")):
            print(f"{value}: {count} ({ratio:.2%})")
    elif action == "8":
        data = Path(input("File: ").strip().strip('"')).read_bytes()
        print(f"\nEntropy: {shannon_entropy(data):.6f} bits/byte")
        distribution = byte_distribution(data)
        for value, count in sorted(
            enumerate(distribution), key=lambda item: item[1], reverse=True
        )[:10]:
            if count:
                print(f"0x{value:02X}: {count}")
        print("High entropy does not prove encryption.\n")
    elif action == "9":
        changed, total, ratio = avalanche_effect(
            input("First message: ").encode(), input("Second message: ").encode()
        )
        print(f"\nChanged bits: {changed} / {total}\nDifference: {ratio:.2f}%\n")
    elif action == "10":
        result = create_rsa_demo(int(input("p: ")), int(input("q: ")), int(input("e [65537]: ") or "65537"))
        print("\n" + json.dumps(asdict(result), indent=2) + "\n")
    elif action == "11":
        result = demonstrate(
            int(input("Prime p: ")),
            int(input("Generator g: ")),
            int(input("Alice private value: ")),
            int(input("Bob private value: ")),
        )
        print("\n" + json.dumps(asdict(result), indent=2))
        print("WARNING: without authentication this exchange is vulnerable to MITM.\n")
    elif action == "12":
        algorithm = input("Algorithm [md5/sha1]: ").strip().casefold()
        print("WARNING: this algorithm is cryptographically broken for security use.")
        print(legacy_hash(input("Text: ").encode(), algorithm) + "\n")
    elif action == "13":
        operation = input("Operation [gcd/inverse/prime]: ").strip().casefold()
        first = int(input("First integer: "))
        if operation == "prime":
            print("PRIME\n" if is_prime(first) else "COMPOSITE\n")
        else:
            second = int(input("Second integer/modulus: "))
            print(f"\n{gcd(first, second) if operation == 'gcd' else modular_inverse(first, second)}\n")
    else:
        raise ValidationError("Invalid selection.")


def _interactive_benchmark() -> None:
    print("\nLOCAL BENCHMARK")
    for result in run_benchmark():
        print(f"{result.algorithm:24} {result.mebibytes_per_second:10.2f} MiB/s")
    print()


def _interactive_settings() -> None:
    config = load_config()
    print("\nSETTINGS\n" + json.dumps(asdict(config), indent=2))
    print("[1] Toggle logging\n[2] Toggle debug mode\n[0] Back")
    action = input("Select an option: ").strip()
    if action == "0":
        return
    key = "logging_enabled" if action == "1" else "debug" if action == "2" else None
    if key is None:
        raise ValidationError("Invalid selection.")
    updated = update_config(config, key, str(not getattr(config, key)).lower())
    save_config(updated)
    print(f"\n{key} is now {getattr(updated, key)}.\n")


def _interactive_analyzer() -> None:
    print("\nCRYPTOGRAPHIC ANALYZER")
    print("[1] Paste a value\n[2] Analyze a file\n[0] Back")
    action = input("Select an option: ").strip()
    if action == "0":
        return
    if action == "1":
        result = analyze_text(input("Value: "))
    elif action == "2":
        source = Path(input("Input file: ").strip().strip('"'))
        result = analyze_bytes(source.read_bytes())
    else:
        raise ValidationError("Invalid selection.")
    _print_analysis(result)
    print()


def _print_analysis(result: AnalysisResult) -> None:
    print("\n" + "=" * 40)
    print("  INPUT ANALYSIS")
    print("=" * 40)

    # ── Representation / candidates ──
    print("\nRepresentation:")
    for candidate in result.candidates:
        print(f"  {candidate.kind} [{candidate.confidence}]")
        print(f"    {candidate.evidence}")

    # ── Container ──
    if result.container is not None:
        print("\nContainer:")
        print(f"  Format: {result.container.format}")
        print(f"  Header: {result.container.header}")
        if result.container.salt is not None:
            print(f"  Salt: {result.container.salt}")
        if result.cipher is not None:
            print(f"\nCipher:\n  {result.cipher}")
        if result.kdf is not None:
            print(f"\nKDF:\n  {result.kdf}")

    # ── Structure (dot-separated / JWT / JWE) ──
    if result.structure is not None:
        print(f"\nStructure:")
        print(f"  {result.structure.kind} [{len(result.structure.segments)} segments]")
        for index, segment in enumerate(result.structure.segments, 1):
            print(f"\n  Segment {index}:")
            print(f"    Encoding: {segment.representation} [{segment.confidence}]")
            if segment.decoded_type is not None:
                print(f"    Decoded: {segment.decoded_type}")
            if segment.value is not None:
                print(f"    Value: {segment.value!r}")
            if len(segment.decode_path) > 1:
                print(f"    Decode path: {' -> '.join(segment.decode_path)}")
        print(f"\n  Recognized standard:\n    {result.structure.recognized_standard}")

    # ── Decode path (non-structured) ──
    if result.decode_layers:
        print("\nDecode path:")
        print("  " + " -> ".join(result.decode_layers))

    # ── Decoded text ──
    if result.decoded_text is not None:
        print("\nDecoded text:")
        print(f"  {result.decoded_text!r}")

    # ── Text characteristics ──
    if result.classification:
        print("\nText characteristics:")
        for characteristic in result.classification:
            print(f"  - {characteristic}")

    # ── Cryptographic metadata ──
    if result.cryptographic_metadata:
        print("\nCryptographic metadata:")
        for meta in result.cryptographic_metadata:
            print(f"  - {meta}")

    # ── Suggested analysis ──
    if result.suggestions:
        print("\nSuggested analysis:")
        for suggestion in result.suggestions:
            print(f"  - {suggestion}")

    # ── Decoded size ──
    if result.decoded_bytes is not None:
        print(f"\nDecoded size:\n  {result.decoded_bytes} bytes")

    # ── Statistical properties ──
    if result.entropy_bits_per_byte is None:
        # Improvement 3: Suppressed for tiny samples.
        if result.statistical_note:
            print("\nStatistical analysis:")
            print(f"  {result.statistical_note}")
    elif result.sample_limited_max_entropy is not None and result.sample_limited_max_entropy < 8.0:
        # Improvement 2: Three-tier display for small samples.
        print("\nStatistical characteristics:")
        print(f"\n  Observed Shannon entropy:")
        print(f"    {result.entropy_bits_per_byte:.4f} bits/byte")
        print(f"\n  Sample-limited maximum:")
        print(f"    {result.sample_limited_max_entropy:.4f} bits/byte")
        print(f"\n  Theoretical byte maximum:")
        print(f"    8.0000 bits/byte")
        print(f"\n  Assessment:")
        print(f"    {result.statistical_note}")
    else:
        # Full-size sample: standard display.
        print("\nStatistical characteristics:")
        print(f"  Entropy = {result.entropy_bits_per_byte:.4f} bits/byte")
        print(f"  {result.statistical_note}")

    # ── Warning ──
    print("\nImportant:")
    print(f"  {result.warning}")


def _select_enum(label: str, enum_type):
    values = list(enum_type)
    print(f"\n{label}:")
    for index, value in enumerate(values, 1):
        print(f"[{index}] {value.value}")
    choice = input("Select an option: ").strip()
    if not choice.isdigit() or not 1 <= int(choice) <= len(values):
        raise ValidationError("Invalid selection.")
    return values[int(choice) - 1]


def _yes_no(prompt: str, default: bool) -> bool:
    marker = "Y/n" if default else "y/N"
    answer = input(f"{prompt} [{marker}]: ").strip().casefold()
    if not answer:
        return default
    if answer in {"y", "yes"}:
        return True
    if answer in {"n", "no"}:
        return False
    raise ValidationError("Answer must be yes or no.")


def _progress_reporter():
    """Return a per-operation progress callback with measured throughput."""
    started = time.perf_counter()

    def report(done: int, total: int) -> None:
        percentage = 100 if total == 0 else int(done / total * 100)
        elapsed = max(time.perf_counter() - started, 1e-9)
        speed = done / (1024 * 1024) / elapsed
        print(
            f"\rProgress: {percentage:3}% | Speed: {speed:8.2f} MiB/s",
            end="",
            flush=True,
        )

    return report


def _default_decrypted_path(source: Path) -> Path:
    if source.suffix.casefold() != ".cryptx":
        raise ValidationError(
            "A custom output path is required when the input does not end in .cryptx."
        )
    return source.with_suffix("")


def _confirm_existing_destination(destination: Path) -> bool:
    if not destination.exists():
        return False
    answer = input(
        f"Destination already exists: {destination}\nOverwrite it? [y/N]: "
    ).strip().casefold()
    if answer in {"y", "yes"}:
        return True
    raise ValidationError(
        "Operation cancelled. Choose a different output file to preserve the existing file."
    )


def _b64(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


def _unb64(value: str) -> bytes:
    return base64.b64decode(value, validate=True)


def _checksum_value(value: str) -> str:
    candidate = Path(value.strip().strip('"'))
    if candidate.is_file() and not candidate.is_symlink():
        try:
            content = candidate.read_text(encoding="utf-8").strip()
        except OSError as exc:
            raise ValidationError(f"Unable to read checksum file: {candidate}") from exc
        if not content:
            raise ValidationError("Checksum file is empty.")
        return content.split()[0]
    return value


_INTERACTIVE_HANDLERS = {
    1: _interactive_text_crypto,
    2: _interactive_file_crypto,
    3: _interactive_hashing,
    4: _interactive_hmac,
    5: _interactive_signatures,
    6: _interactive_public_key,
    7: _interactive_keys,
    8: _interactive_passwords,
    9: _interactive_random,
    10: _interactive_encoding,
    11: _interactive_integrity,
    12: _interactive_certificate,
    13: _interactive_vault,
    14: _interactive_lab,
    15: _interactive_benchmark,
    16: _interactive_settings,
    17: _interactive_analyzer,
}
