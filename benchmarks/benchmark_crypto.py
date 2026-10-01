#!/usr/bin/env python3

"""
Cryptographic operation timing benchmark.

Measures wall-clock time for Argon2id hashing, AES-GCM-SIV
encrypt/decrypt, master-key derivation, and the full save_password
pipeline.

By default this runs at production Argon2id parameters (100 iterations,
64 MiB).  Set SPG_TEST_KDF=1 for a quick sanity run with minimal KDF.

Usage:
    python benchmarks/benchmark_crypto.py
    python benchmarks/benchmark_crypto.py -n 20
    python benchmarks/benchmark_crypto.py -c encrypt_decrypt argon2id_hash
    SPG_TEST_KDF=1 python benchmarks/benchmark_crypto.py -n 50
"""

import argparse
import json
import os
import secrets
import statistics
import time

from secure_password_generator.constants import (
    ARGON2_ITERATIONS,
    ARGON2_MEMORY_COST,
)
from secure_password_generator.crypto import (
    argon2id_hash,
    decrypt_data,
    derive_master_key,
    encrypt_data,
    initialize_security_files,
)

DEFAULT_ITERATIONS = 10

OPERATIONS = {
    "argon2id_hash": {
        "label": "argon2id_hash() -- per-password Argon2id digest",
    },
    "derive_master_key": {
        "label": "derive_master_key() -- master password KDF",
    },
    "encrypt_decrypt": {
        "label": "encrypt_data() + decrypt_data() -- AES-GCM-SIV round-trip",
    },
    "encrypt_large": {
        "label": "encrypt_data() -- 4 KB payload (large vault record)",
    },
}


def _bench_argon2id_hash(iterations: int) -> list[float]:
    times: list[float] = []
    for i in range(iterations):
        pw = f"BenchmarkPassword{i}!"
        t0 = time.perf_counter()
        argon2id_hash(pw)
        times.append(time.perf_counter() - t0)
    return times


def _bench_derive_master_key(iterations: int) -> list[float]:
    salt = secrets.token_bytes(32)
    times: list[float] = []
    for i in range(iterations):
        pw = f"MasterBench{i}!Xz"
        t0 = time.perf_counter()
        derive_master_key(pw, salt=salt)
        times.append(time.perf_counter() - t0)
    return times


def _bench_encrypt_decrypt(iterations: int) -> list[float]:
    key = secrets.token_bytes(32)
    payload = json.dumps({
        "password": "s3cure!Pass",
        "label": "Benchmark",
        "timestamp": "Mon, Jan 01, 2024 12:00:00:000000 PM",
    })
    times: list[float] = []
    for _ in range(iterations):
        t0 = time.perf_counter()
        blob = encrypt_data(payload, key)
        decrypt_data(blob, key)
        times.append(time.perf_counter() - t0)
    return times


def _bench_encrypt_large(iterations: int) -> list[float]:
    key = secrets.token_bytes(32)
    payload = "x" * 4096
    times: list[float] = []
    for _ in range(iterations):
        t0 = time.perf_counter()
        encrypt_data(payload, key)
        times.append(time.perf_counter() - t0)
    return times


_RUNNERS = {
    "argon2id_hash": _bench_argon2id_hash,
    "derive_master_key": _bench_derive_master_key,
    "encrypt_decrypt": _bench_encrypt_decrypt,
    "encrypt_large": _bench_encrypt_large,
}


def print_report(op_key: str, times: list[float], iterations: int) -> None:
    info = OPERATIONS[op_key]
    total = sum(times)
    mean_ms = statistics.mean(times) * 1000
    ops_per_sec = iterations / total if total > 0 else 0

    print()
    print("=" * 70)
    print(f"  Operation:    {info['label']}")
    print(f"  Iterations:   {iterations}")
    print(f"  KDF params:   iterations={ARGON2_ITERATIONS}, "
          f"memory={ARGON2_MEMORY_COST // 1024} MiB")
    print("=" * 70)
    print(f"  Total time:   {total:.3f}s")
    print(f"  Mean:         {mean_ms:.3f} ms/op")
    if len(times) > 1:
        p99_ms = sorted(times)[int(len(times) * 0.99)] * 1000
        stddev_ms = statistics.pstdev(times) * 1000
        print(f"  p99:          {p99_ms:.3f} ms/op")
        print(f"  StdDev:       {stddev_ms:.3f} ms")
    print(f"  Throughput:   {ops_per_sec:.2f} ops/sec")
    print()


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Benchmark cryptographic operations."
    )
    parser.add_argument(
        "-n", "--iterations",
        type=int,
        default=DEFAULT_ITERATIONS,
        help=f"Iterations per operation (default: {DEFAULT_ITERATIONS})",
    )
    parser.add_argument(
        "-c", "--config",
        choices=list(OPERATIONS.keys()),
        nargs="*",
        default=list(OPERATIONS.keys()),
        help="Operations to benchmark (default: all)",
    )
    args = parser.parse_args()

    kdf_mode = (
        "TEST (SPG_TEST_KDF=1)" if os.environ.get("SPG_TEST_KDF")
        else "PRODUCTION"
    )

    print()
    print("Cryptographic Operations: Timing Benchmark")
    print("============================================")
    print(f"  KDF mode: {kdf_mode}")

    # Ensure security files exist for argon2id_hash (needs pepper)
    initialize_security_files()

    for key in args.config:
        runner = _RUNNERS[key]
        times = runner(args.iterations)
        print_report(key, times, args.iterations)

    print("Done.")


if __name__ == "__main__":
    main()
