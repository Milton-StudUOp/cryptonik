"""EDUCATIONAL ANALYSIS — high entropy does not prove encryption."""

from __future__ import annotations

import hashlib
import math
from collections import Counter


def frequency_analysis(text: str, ngram: int = 1) -> list[tuple[str, int, float]]:
    """Return descending character, bigram, or trigram frequencies."""
    if ngram not in {1, 2, 3}:
        raise ValueError("ngram must be 1, 2, or 3")
    normalized = "".join(char.upper() for char in text if char.isalpha())
    values = [normalized[index : index + ngram] for index in range(len(normalized) - ngram + 1)]
    counts = Counter(values)
    total = len(values)
    return [(value, count, count / total if total else 0.0) for value, count in counts.most_common()]


def shannon_entropy(data: bytes) -> float:
    """Calculate empirical Shannon entropy in bits per byte."""
    if not data:
        return 0.0
    counts = Counter(data)
    length = len(data)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


def byte_distribution(data: bytes) -> tuple[int, ...]:
    """Return counts for every possible byte value, from 0 through 255."""
    counts = Counter(data)
    return tuple(counts[value] for value in range(256))


def avalanche_effect(first: bytes, second: bytes, algorithm: str = "sha256") -> tuple[int, int, float]:
    """Compare changed digest bits for two inputs."""
    left = hashlib.new(algorithm, first).digest()
    right = hashlib.new(algorithm, second).digest()
    changed = sum((a ^ b).bit_count() for a, b in zip(left, right, strict=True))
    total = len(left) * 8
    return changed, total, changed / total * 100


def legacy_hash(data: bytes, algorithm: str) -> str:
    """Calculate MD5/SHA-1 strictly for compatibility demonstrations."""
    if algorithm not in {"md5", "sha1"}:
        raise ValueError("Legacy algorithm must be md5 or sha1")
    return hashlib.new(algorithm, data, usedforsecurity=False).hexdigest()
