"""Tests for explicitly educational cryptography and analysis."""

import pytest

from cryptosuite.lab import (
    affine,
    avalanche_effect,
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


def test_classical_cipher_round_trips():
    assert caesar(caesar("Hello, World!", 7), 7, decrypt=True) == "Hello, World!"
    assert vigenere(vigenere("ATTACK AT DAWN", "LEMON"), "LEMON", decrypt=True) == "ATTACK AT DAWN"
    assert affine(affine("Affine Cipher", 5, 8), 5, 8, decrypt=True) == "Affine Cipher"
    assert rail_fence(rail_fence("WEAREDISCOVERED", 3), 3, decrypt=True) == "WEAREDISCOVERED"


def test_playfair_known_example_and_hill_round_trip():
    assert playfair("HIDETHEGOLDINTHETREESTUMP", "PLAYFAIR EXAMPLE") == "BMODZBXDNABEKUDMUIXMMOUVIF"
    encrypted = hill_2x2("HELP", ((3, 3), (2, 5)))
    assert hill_2x2(encrypted, ((3, 3), (2, 5)), decrypt=True) == "HELP"


def test_frequency_entropy_and_avalanche():
    frequencies = frequency_analysis("ABRACADABRA")
    assert frequencies[0][:2] == ("A", 5)
    assert shannon_entropy(bytes(range(256))) == pytest.approx(8.0)
    changed, total, percentage = avalanche_effect(b"Hello", b"hello")
    assert 0 < changed < total == 256
    assert percentage == pytest.approx(changed / total * 100)


def test_rsa_and_diffie_hellman_demonstrations():
    rsa = create_rsa_demo(61, 53, 17)
    assert rsa.n == 3233
    assert rsa.phi == 3120
    assert rsa.d == 2753
    assert rsa.decrypt(rsa.encrypt(65)) == 65
    exchange = demonstrate(23, 5, 6, 15)
    assert exchange.alice_shared == exchange.bob_shared


def test_legacy_hash_and_number_theory_are_educational_helpers():
    assert legacy_hash(b"abc", "md5") == "900150983cd24fb0d6963f7d28e17f72"
    assert gcd(54, 24) == 6
    assert modular_inverse(17, 3120) == 2753
    assert is_prime(61)
    assert not is_prime(60)
