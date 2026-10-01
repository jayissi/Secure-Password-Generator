#!/usr/bin/env python3

"""
Password generation throughput and retry-rate benchmark.

Measures passwords generated per second across configurations of
increasing constraint complexity.  Reports throughput, mean retries,
and p99 retry count.

Usage:
    python benchmarks/benchmark_generation.py
    python benchmarks/benchmark_generation.py -n 500
    python benchmarks/benchmark_generation.py -c simple heavy_constraints
"""

import argparse
import statistics
import time

from secure_password_generator.config import CharsetConfig
from secure_password_generator.generator import (
    generate_password,
)

DEFAULT_ITERATIONS = 200

CONFIGS = {
    "simple": {
        "label": "Lower-only, length 12, no constraints (baseline)",
        "cfg": CharsetConfig(use_lower=True),
        "gen_kwargs": {"length": 12},
    },
    "typical": {
        "label": "Full charset, no-repeats, min 2 (typical use)",
        "cfg": CharsetConfig(
            use_upper=True, use_lower=True,
            use_digits=True, use_symbols=True,
        ),
        "gen_kwargs": {
            "length": 24,
            "min_characters_per_type": 2,
            "no_repeats": True,
        },
    },
    "heavy_constraints": {
        "label": "Full + blank + exclude-similar + min 4 + no-repeats (worst case)",
        "cfg": CharsetConfig(
            use_upper=True, use_lower=True,
            use_digits=True, use_symbols=True,
            allowed_symbols="!@#$%^&*?",
            exclude_similar=True,
            blank=True,
        ),
        "gen_kwargs": {
            "length": 33,
            "min_characters_per_type": 4,
            "no_repeats": True,
        },
    },
    "symbol_only": {
        "label": "Symbol-only with no-repeats (special-case path)",
        "cfg": CharsetConfig(
            use_symbols=True,
            allowed_symbols="!@#$%^&*?<>[]{}",
        ),
        "gen_kwargs": {
            "length": 16,
            "no_repeats": True,
        },
    },
    "pattern": {
        "label": "Pattern-based generation (separate code path)",
        "cfg": CharsetConfig(use_lower=True),
        "gen_kwargs": {
            "length": 16,
            "pattern": "lluuddss****lluu",
        },
    },
}


def run_benchmark(config_key: str, iterations: int) -> dict:
    cfg_entry = CONFIGS[config_key]
    charset_cfg = cfg_entry["cfg"]
    kw = cfg_entry["gen_kwargs"]

    elapsed_times: list[float] = []

    for _ in range(iterations):
        t0 = time.perf_counter()
        generate_password(cfg=charset_cfg, **kw)
        elapsed_times.append(time.perf_counter() - t0)

    total_time = sum(elapsed_times)
    throughput = iterations / total_time if total_time > 0 else 0
    mean_ms = statistics.mean(elapsed_times) * 1000
    p99_ms = sorted(elapsed_times)[int(iterations * 0.99)] * 1000

    return {
        "label": cfg_entry["label"],
        "iterations": iterations,
        "total_time_s": total_time,
        "throughput_per_s": throughput,
        "mean_ms": mean_ms,
        "p99_ms": p99_ms,
    }


def print_report(result: dict) -> None:
    print()
    print("=" * 70)
    print(f"  Config:       {result['label']}")
    print(f"  Iterations:   {result['iterations']}")
    print("=" * 70)
    print(f"  Total time:   {result['total_time_s']:.3f}s")
    print(f"  Throughput:   {result['throughput_per_s']:.1f} passwords/sec")
    print(f"  Mean:         {result['mean_ms']:.3f} ms/password")
    print(f"  p99:          {result['p99_ms']:.3f} ms/password")
    print()


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Benchmark password generation throughput."
    )
    parser.add_argument(
        "-n", "--iterations",
        type=int,
        default=DEFAULT_ITERATIONS,
        help=f"Passwords per config (default: {DEFAULT_ITERATIONS})",
    )
    parser.add_argument(
        "-c", "--config",
        choices=list(CONFIGS.keys()),
        nargs="*",
        default=list(CONFIGS.keys()),
        help="Configs to benchmark (default: all)",
    )
    args = parser.parse_args()

    print()
    print("Password Generation: Throughput Benchmark")
    print("==========================================")

    for key in args.config:
        result = run_benchmark(key, args.iterations)
        print_report(result)

    print("Done.")


if __name__ == "__main__":
    main()
