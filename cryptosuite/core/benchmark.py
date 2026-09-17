"""Local cryptographic throughput measurements; values are never hardcoded."""

from __future__ import annotations

import time
from dataclasses import dataclass

from cryptosuite.core.hashing import HashAlgorithm, digest
from cryptosuite.core.symmetric import SymmetricAlgorithm, encrypt, generate_key


@dataclass(frozen=True, slots=True)
class BenchmarkResult:
    algorithm: str
    mebibytes_per_second: float


def run_benchmark(data_size: int = 4 * 1024 * 1024, rounds: int = 3) -> tuple[BenchmarkResult, ...]:
    """Measure representative in-memory operations on the current machine."""
    data = bytes(data_size)
    results = []
    for algorithm in (HashAlgorithm.SHA256, HashAlgorithm.SHA512):
        results.append(_measure(algorithm.value, data_size, rounds, lambda a=algorithm: digest(data, a)))
    for algorithm in SymmetricAlgorithm:
        key = generate_key()
        results.append(_measure(algorithm.value, data_size, rounds, lambda a=algorithm, k=key: encrypt(data, k, a)))
    return tuple(results)


def _measure(name: str, size: int, rounds: int, operation) -> BenchmarkResult:
    started = time.perf_counter()
    for _ in range(rounds):
        operation()
    elapsed = max(time.perf_counter() - started, 1e-9)
    return BenchmarkResult(name, size * rounds / (1024 * 1024) / elapsed)

