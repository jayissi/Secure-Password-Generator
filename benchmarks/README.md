# benchmarks/ -- Performance Diagnostic Tools

> Back to [main README](../README.md)

This directory contains standalone CLI scripts that measure performance
characteristics of the Secure Password Generator.  They are **not tests**
-- they produce human-readable reports with no pass/fail assertions.

The pytest test suite (`tests/`) verifies correctness.  These benchmarks
answer a different question: "How fast is it?"

|          Script           | What it measures                         |
|:-------------------------:|------------------------------------------|
|  `benchmark_strength.py`  | Strength scoring consistency and flicker |
| `benchmark_generation.py` | Password generation throughput           |
|   `benchmark_crypto.py`   | Cryptographic operation timing           |

---

## Quick Start

```bash
# Run all three with defaults
python benchmarks/benchmark_strength.py
python benchmarks/benchmark_generation.py
python benchmarks/benchmark_crypto.py

# Quick sanity run with reduced Argon2id (for crypto benchmark)
SPG_TEST_KDF=1 python benchmarks/benchmark_crypto.py -n 20
```

---

## File Reference

### `benchmark_strength.py` -- scoring consistency

Generates N passwords per configuration and reports the distribution of
strength scores (1--10), mean, standard deviation, and whether **flicker**
(more than one distinct score for a given config) was observed.

**When to run:** after changing `calculate_password_strength()`,
`build_charset()`, or the scoring bonus/penalty logic.  Flicker indicates
the scoring algorithm is sensitive to randomness in the generated password,
which degrades the user experience.

**Bundled configurations:** Full + Blank, Full (no blank), Short (upper +
lower only).

```bash
python benchmarks/benchmark_strength.py -n 200
python benchmarks/benchmark_strength.py -c blank_full short_simple
```

**Sample output:**

```text
======================================================================
  Config:      Full + Blank (blank-space config)
  Length:      33
  Pool size:   65
  Iterations:  200
======================================================================
  Strength scores:
    Score 10:  200 (100.0%) ##################################################
    Mean:   10.00
    StdDev: 0.000
    Range:  10 - 10

  Flicker (>1 distinct score): NO
```

---

### `benchmark_generation.py` -- generation throughput

Measures passwords generated per second, mean time per password, and p99
latency across configurations of increasing constraint complexity.

**When to run:** after changing `generate_password()`, the constraint
enforcement logic, or `_validate_generation_feasibility()`.  A code change
that increases retries would still pass all pytest tests but degrade
real-world throughput -- this benchmark catches that.

**Bundled configurations:**

|         Key         | Description                                         |
|:-------------------:|-----------------------------------------------------|
|      `simple`       | Lower-only, length 12, no constraints (baseline)    |
|      `typical`      | Full charset, no-repeats, min 2 per type            |
| `heavy_constraints` | Full + blank + exclude-similar + min 4 + no-repeats |
|    `symbol_only`    | Symbol-only with no-repeats (special-case path)     |
|      `pattern`      | Pattern-based generation (separate code path)       |

```bash
python benchmarks/benchmark_generation.py -n 500
python benchmarks/benchmark_generation.py -c simple heavy_constraints
```

**Sample output:**

```text
======================================================================
  Config:       Full charset, no-repeats, min 2 (typical use)
  Iterations:   200
======================================================================
  Total time:   0.018s
  Throughput:   11036.3 passwords/sec
  Mean:         0.091 ms/password
  p99:          0.285 ms/password
```

---

### `benchmark_crypto.py` -- cryptographic operation timing

Measures wall-clock time for individual cryptographic operations.  Runs at
**production Argon2id parameters** by default (100 iterations, 64 MiB) so
the numbers reflect real-world performance.  Set `SPG_TEST_KDF=1` for a
quick sanity run.

**When to run:** after tuning Argon2id parameters (`ARGON2_ITERATIONS`,
`ARGON2_MEMORY_COST`), changing the encryption scheme, or evaluating
hardware suitability.

**Bundled operations:**

|         Key         | Description                                  |
|:-------------------:|----------------------------------------------|
|   `argon2id_hash`   | Per-password Argon2id digest (salt + pepper) |
| `derive_master_key` | Master password KDF (Argon2id)               |
|  `encrypt_decrypt`  | AES-GCM-SIV encrypt + decrypt round-trip     |
|   `encrypt_large`   | AES-GCM-SIV encrypt with 4 KB payload        |

```bash
python benchmarks/benchmark_crypto.py -n 20
python benchmarks/benchmark_crypto.py -c encrypt_decrypt argon2id_hash
SPG_TEST_KDF=1 python benchmarks/benchmark_crypto.py -n 50
```

**Sample output (production KDF):**

```text
Cryptographic Operations: Timing Benchmark
============================================
  KDF mode: PRODUCTION

======================================================================
  Operation:    argon2id_hash() -- per-password Argon2id digest
  Iterations:   10
  KDF params:   iterations=100, memory=64 MiB
======================================================================
  Total time:   12.340s
  Mean:         1234.000 ms/op
  p99:          1280.000 ms/op
  Throughput:   0.81 ops/sec
```

---

## Notes

- These scripts import from the installed `secure_password_generator`
  package.  Run `python -m pip install -e .` first.
- `benchmark_crypto.py` uses production Argon2id by default and can take
  30+ seconds.  Use `SPG_TEST_KDF=1` for quick runs.
- All scripts accept `-n` to set the iteration count and `-c` to select
  specific configurations/operations.
