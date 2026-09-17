"""EDUCATIONAL DIFFIE-HELLMAN — unauthenticated and vulnerable to MITM."""

from __future__ import annotations

from dataclasses import dataclass

from cryptosuite.utils.exceptions import ValidationError


@dataclass(frozen=True, slots=True)
class DiffieHellmanResult:
    alice_public: int
    bob_public: int
    alice_shared: int
    bob_shared: int


def demonstrate(p: int, g: int, alice_private: int, bob_private: int) -> DiffieHellmanResult:
    """Demonstrate modular DH; this deliberately provides no authentication."""
    if p < 5 or not 2 <= g < p or not 2 <= alice_private < p or not 2 <= bob_private < p:
        raise ValidationError("Invalid educational Diffie-Hellman parameters.")
    alice_public = pow(g, alice_private, p)
    bob_public = pow(g, bob_private, p)
    return DiffieHellmanResult(
        alice_public,
        bob_public,
        pow(bob_public, alice_private, p),
        pow(alice_public, bob_private, p),
    )

