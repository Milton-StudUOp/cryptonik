"""Educational cryptography only; never for production data protection."""

from cryptosuite.lab.analysis import (
    avalanche_effect,
    byte_distribution,
    frequency_analysis,
    legacy_hash,
    shannon_entropy,
)
from cryptosuite.lab.classical import (
    affine,
    caesar,
    hill_2x2,
    playfair,
    rail_fence,
    vigenere,
)
from cryptosuite.lab.diffie_hellman_demo import demonstrate
from cryptosuite.lab.number_theory import gcd, is_prime, modular_inverse
from cryptosuite.lab.rsa_demo import create_rsa_demo

__all__ = [
    "affine",
    "avalanche_effect",
    "byte_distribution",
    "caesar",
    "create_rsa_demo",
    "demonstrate",
    "frequency_analysis",
    "gcd",
    "hill_2x2",
    "is_prime",
    "legacy_hash",
    "modular_inverse",
    "playfair",
    "rail_fence",
    "shannon_entropy",
    "vigenere",
]
