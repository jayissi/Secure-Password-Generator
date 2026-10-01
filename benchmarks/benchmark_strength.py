#!/usr/bin/env python3

"""
Password strength scoring consistency test.

Generates N passwords per configuration and reports score distributions,
standard deviation, and flicker (score variance) for each config.
"""

import argparse
import statistics
from collections import Counter

from secure_password_generator.config import CharsetConfig
from secure_password_generator.generator import (
    calculate_password_strength,
    compute_charset_size,
    generate_password,
)

DEFAULT_ITERATIONS = 100

CONFIGS = {
    "blank_full": {
        "label": "Full + Blank (blank-space config)",
        "cfg": CharsetConfig(
            use_upper=True,
            use_lower=True,
            use_digits=True,
            use_symbols=True,
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
    "full_no_blank": {
        "label": "Full charset, no blank",
        "cfg": CharsetConfig(
            use_upper=True,
            use_lower=True,
            use_digits=True,
            use_symbols=True,
            exclude_similar=False,
            allowed_symbols=None,
            blank=False,
        ),
        "gen_kwargs": {
            "length": 24,
            "min_characters_per_type": 2,
            "no_repeats": True,
        },
    },
    "short_simple": {
        "label": "Short password, upper+lower only",
        "cfg": CharsetConfig(
            use_upper=True,
            use_lower=True,
            use_digits=False,
            use_symbols=False,
            exclude_similar=False,
            allowed_symbols=None,
            blank=False,
        ),
        "gen_kwargs": {
            "length": 10,
            "min_characters_per_type": 1,
            "no_repeats": False,
        },
    },
}


def run_test(config_key: str, iterations: int) -> dict:
    cfg_entry = CONFIGS[config_key]
    charset_cfg = cfg_entry["cfg"]
    kw = cfg_entry["gen_kwargs"]
    pool_size = compute_charset_size(charset_cfg)

    scores: list[int] = []
    passwords: list[str] = []

    for _ in range(iterations):
        pw = generate_password(cfg=charset_cfg, **kw)
        s = calculate_password_strength(pw, charset_size=pool_size)
        scores.append(s)
        passwords.append(pw)

    return {
        "label": cfg_entry["label"],
        "pool_size": pool_size,
        "length": kw["length"],
        "iterations": iterations,
        "scores": scores,
        "passwords": passwords,
    }


def print_distribution(label: str, scores: list[int]) -> None:
    dist = Counter(scores)
    total = len(scores)
    print(f"  {label}:")
    for score in sorted(dist):
        count = dist[score]
        pct = count / total * 100
        bar = "#" * int(pct / 2)
        print(f"    Score {score:>2}: {count:>4} ({pct:5.1f}%) {bar}")
    print(f"    Mean:   {statistics.mean(scores):.2f}")
    print(f"    StdDev: {statistics.pstdev(scores):.3f}")
    print(f"    Range:  {min(scores)} - {max(scores)}")


def print_report(result: dict) -> None:
    scores = result["scores"]
    n = result["iterations"]

    print()
    print("=" * 70)
    print(f"  Config:      {result['label']}")
    print(f"  Length:      {result['length']}")
    print(f"  Pool size:   {result['pool_size']}")
    print(f"  Iterations:  {n}")
    print("=" * 70)

    print_distribution("Strength scores", scores)

    flicker = len(set(scores)) > 1

    print()
    print(f"  Flicker (>1 distinct score): {'YES' if flicker else 'NO'}")
    print()


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Test password strength scoring consistency."
    )
    parser.add_argument(
        "-n", "--iterations",
        type=int,
        default=DEFAULT_ITERATIONS,
        help=f"Number of passwords per config (default: {DEFAULT_ITERATIONS})",
    )
    parser.add_argument(
        "-c", "--config",
        choices=list(CONFIGS.keys()),
        nargs="*",
        default=list(CONFIGS.keys()),
        help="Configs to test (default: all)",
    )
    args = parser.parse_args()

    print()
    print("Password Strength Scoring: Consistency Test")
    print("=============================================")

    for key in args.config:
        result = run_test(key, args.iterations)
        print_report(result)

    print("Done.")


if __name__ == "__main__":
    main()
