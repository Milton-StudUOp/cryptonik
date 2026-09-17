"""End-to-end tests for direct CLI workflows using real files and keys."""



from cryptosuite.cli import run_cli
from cryptosuite.config import AppConfig
from cryptosuite.keys.key_generator import (
    KeyAlgorithm,
    generate_private_key,
    serialize_private_key,
    serialize_public_key,
)


def _passwords(monkeypatch, *values):
    iterator = iter(values)
    monkeypatch.setattr("getpass.getpass", lambda _: next(iterator))


def test_cli_password_file_encrypt_decrypt_and_integrity(tmp_path, monkeypatch, capsys):
    source = tmp_path / "document.bin"
    source.write_bytes(bytes(range(256)) * 1000)
    encrypted = tmp_path / "document.cryptx"
    restored = tmp_path / "restored.bin"
    _passwords(monkeypatch, "password", "password")
    assert run_cli(["encrypt", str(source), "--output", str(encrypted)], AppConfig()) == 0
    _passwords(monkeypatch, "password")
    assert run_cli(["decrypt", str(encrypted), "--output", str(restored)], AppConfig()) == 0
    assert restored.read_bytes() == source.read_bytes()
    assert run_cli(["hash", str(source)], AppConfig()) == 0
    digest = capsys.readouterr().out.strip().splitlines()[-1]
    assert run_cli(["integrity", str(source), digest], AppConfig()) == 0
    checksum_file = tmp_path / "checksum.txt"
    checksum_file.write_text(f"{digest}  document.bin\n", encoding="utf-8")
    assert run_cli(["integrity", str(source), str(checksum_file)], AppConfig()) == 0


def test_cli_streaming_sign_and_verify(tmp_path, monkeypatch):
    document = tmp_path / "document.bin"
    document.write_bytes(b"signed content" * 10_000)
    private = generate_private_key(KeyAlgorithm.ED25519)
    private_path = tmp_path / "private.pem"
    public_path = tmp_path / "public.pem"
    private_path.write_bytes(serialize_private_key(private, "key password"))
    public_path.write_bytes(serialize_public_key(private.public_key()))
    signature = tmp_path / "document.sig"
    _passwords(monkeypatch, "key password")
    assert run_cli(
        ["sign", str(document), "--key", str(private_path), "--output", str(signature)],
        AppConfig(),
    ) == 0
    assert run_cli(
        ["verify", str(document), str(signature), "--key", str(public_path)],
        AppConfig(),
    ) == 0


def test_cli_streaming_public_key_encryption(tmp_path, monkeypatch):
    source = tmp_path / "source.bin"
    source.write_bytes(b"recipient data" * 20_000)
    private = generate_private_key(KeyAlgorithm.X25519)
    private_path = tmp_path / "private.pem"
    public_path = tmp_path / "public.pem"
    private_path.write_bytes(serialize_private_key(private, "key password"))
    public_path.write_bytes(serialize_public_key(private.public_key()))
    encrypted = tmp_path / "source.crypth"
    restored = tmp_path / "restored.bin"
    assert run_cli(
        [
            "public-key",
            "encrypt",
            str(source),
            "--recipient",
            str(public_path),
            "--output",
            str(encrypted),
        ],
        AppConfig(),
    ) == 0
    _passwords(monkeypatch, "key password")
    assert run_cli(
        [
            "public-key",
            "decrypt",
            str(encrypted),
            "--key",
            str(private_path),
            "--output",
            str(restored),
        ],
        AppConfig(),
    ) == 0
    assert restored.read_bytes() == source.read_bytes()


def test_cli_key_store_vault_and_certificate_workflows(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("CRYPTOSUITE_CONFIG_DIR", str(tmp_path / "config"))
    _passwords(monkeypatch, "key password", "key password")
    assert run_cli(
        [
            "keys",
            "generate",
            "--type",
            "ed25519",
            "--name",
            "Test Signing",
            "--purpose",
            "signing",
        ],
        AppConfig(),
    ) == 0
    key_directory = next((tmp_path / "config" / "keys").iterdir())
    identifier = key_directory.name
    assert run_cli(["keys", "info", identifier], AppConfig()) == 0

    vault = tmp_path / "test.vault"
    _passwords(monkeypatch, "master password")
    assert run_cli(["vault", "create", str(vault)], AppConfig()) == 0
    _passwords(monkeypatch, "master password", "secret value")
    assert run_cli(
        ["vault", "add", str(vault), "--kind", "token", "--name", "Test"],
        AppConfig(),
    ) == 0
    _passwords(monkeypatch, "master password")
    assert run_cli(["vault", "list", str(vault)], AppConfig()) == 0

    certificate = tmp_path / "certificate.pem"
    _passwords(monkeypatch, "key password")
    assert run_cli(
        [
            "certificate",
            "self-signed",
            "--key",
            str(key_directory / "private.pem"),
            "--common-name",
            "example.test",
            "--san",
            "example.test",
            "--output",
            str(certificate),
        ],
        AppConfig(),
    ) == 0
    assert run_cli(
        [
            "certificate",
            "validate",
            str(certificate),
            "--ca",
            str(certificate),
            "--hostname",
            "example.test",
        ],
        AppConfig(),
    ) == 0
    assert "VALID" in capsys.readouterr().out


def test_cli_full_lab_commands(tmp_path):
    data = tmp_path / "entropy.bin"
    data.write_bytes(bytes(range(256)))
    commands = [
        ["lab", "vigenere", "ATTACKATDAWN", "--key", "LEMON"],
        ["lab", "affine", "AFFINE", "--a", "5", "--b", "8"],
        ["lab", "rail-fence", "HELLOWORLD", "--rails", "3"],
        ["lab", "playfair", "HIDETHEGOLD", "--key", "MONARCHY"],
        ["lab", "hill", "HELP", "--matrix", "3", "3", "2", "5"],
        ["lab", "diffie-hellman", "--p", "23", "--g", "5", "--alice", "6", "--bob", "15"],
        ["lab", "entropy", str(data)],
        ["lab", "avalanche", "Hello", "hello"],
        ["lab", "legacy-hash", "md5", "abc"],
        ["lab", "number-theory", "inverse", "17", "3120"],
    ]
    for command in commands:
        assert run_cli(command, AppConfig()) == 0
