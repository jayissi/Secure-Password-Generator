# tests/ -- Test Suite Reference

This directory contains all automated tests and diagnostic tools for the
Secure Password Generator.

**Summary:**

|           File            |       Type        | Test count | Runtime |
|:-------------------------:|:-----------------:|:----------:|:-------:|
|     `test_config.py`      |      pytest       |     14     |  < 1 s  |
|     `test_crypto.py`      |      pytest       |     16     |  < 1 s  |
|    `test_generator.py`    |      pytest       |     19     |  < 1 s  |
| `test_strength_pytest.py` |      pytest       |     37     |  < 1 s  |
|   `test_integration.sh`   | Bash (end-to-end) |     52     |  ~40 s  |
|  `benchmark_strength.py`  |  CLI diagnostic   |     --     |  ~1 s   |
|         **Total**         |                   |  **138**   |         |

---

## Prerequisites

Install the package in editable mode with development dependencies:

```bash
pip install -e '.[dev]'
```

For the integration tests, `pwgen` must be on your `PATH` (installed by
the command above).  System dependencies (`shred`, optionally `xclip`)
should also be available -- see `bindep.txt` in the project root.

---

## Quick Start

Run everything in the recommended order:

```bash
# 1. Unit tests (fast, no side effects)
pytest tests/ -v

# 2. Integration tests (creates and destroys vault files)
bash tests/test_integration.sh

# 3. Benchmark (informational -- no pass/fail)
python tests/benchmark_strength.py -n 200
```

---

## Recommended Execution Order

1. **Unit tests** (`pytest tests/ -v`) -- run first.  They are fast
   (under 1 second total), use no disk I/O against the real vault, and
   have no side effects.  Failures here indicate a code regression in the
   core logic.

2. **Integration tests** (`bash tests/test_integration.sh`) -- run second.
   These invoke the `pwgen` CLI end-to-end, creating and destroying
   vault files in `~/.secure_passwords/`.  They take roughly 40 seconds
   because several tests exercise Argon2id key derivation.  The script
   starts with a clean vault (`pwgen -C`) and ends by cleaning up after
   itself.

3. **Benchmark** (`python tests/benchmark_strength.py`) -- run last and
   optionally.  This is a diagnostic tool, not a test.  It reports score
   distributions and flicker across multiple configurations to help tune
   the strength-scoring algorithm.

---

## File Reference

### `test_config.py` -- 14 tests

**Module under test:** `secure_password_generator.config`

**What it covers:**

- `load_config()` raises `ConfigError` (not `sys.exit`) for all error
  conditions:
  - Missing file
  - Unsupported file extension (`.toml`)
  - Invalid YAML syntax
  - Invalid JSON syntax
  - Non-dict YAML (e.g., a list)
  - Unknown configuration keys
- Successful YAML and JSON round-trips (values are read back correctly)
- `blank_space` key is mapped to `blank` via `CONFIG_KEY_MAP`
- Empty YAML file returns an empty dictionary
- `CharsetConfig` dataclass:
  - Default field values are all `False`/`None`
  - Frozen (assignment to fields raises `AttributeError`)
  - Equality comparison between identical instances
  - Hashable (can be used in sets)

**How to run:**

```bash
pytest tests/test_config.py -v
```

---

### `test_crypto.py` -- 16 tests

**Module under test:** `secure_password_generator.crypto`

**What it covers:**

- **Encrypt / decrypt round-trip:**
  - Encrypting and decrypting with the same key recovers the plaintext
  - Decrypting with a different key raises an exception
  - A too-short encrypted blob raises `ValueError`
  - Empty plaintext encrypts and decrypts correctly
- **`combine_keys()` XOR:**
  - XOR with a zero key returns the original
  - XOR of a key with itself returns all zeros
  - Mismatched key lengths raise `ValueError`
- **Master-password complexity (`_validate_master_password`):**
  - Too-short password is rejected
  - Password missing character types is rejected
  - Valid passwords with exactly 3 and all 4 types are accepted
- **`resolve_master_password()` priority chain:**
  - CLI `--master-password` flag takes top priority
  - `SPG_MASTER_PASSWORD` environment variable is used when no CLI flag
  - `--master-password-file` reads the first line of the file
  - Returns `None` when no master password is configured

All `resolve_master_password` tests use `unittest.mock.patch` to isolate
from the real filesystem and environment.

**How to run:**

```bash
pytest tests/test_crypto.py -v
```

---

### `test_generator.py` -- 19 tests

**Module under test:** `secure_password_generator.generator`

**What it covers:**

- **`build_charset()`:**
  - Empty config returns an empty list
  - Single character type returns the correct tuple
  - All five types (upper, lower, digits, symbols, blank) are present
  - Custom `allowed_symbols` restricts the symbol pool
  - `exclude_similar=True` reduces the pool size
- **`compute_charset_size()`:**
  - Minimum is 1 (empty config)
  - Adding `blank=True` adds exactly 1 to the size
- **Pattern minimum-length enforcement:**
  - A short pattern (e.g., `"ld"`) is padded to `MIN_PASSWORD_LENGTH`
  - A long pattern is left unchanged
- **Blank-position constraint (100-iteration stress test):**
  - Generated passwords with `blank=True` never have a space as the
    first or last character
- **`_filter_similar_chars()` LRU cache:**
  - Repeated calls with the same arguments return the same object
  - `exclude_similar=False` returns the original string unchanged
- **`generate_password()` constraints:**
  - Minimum length enforcement (short request is increased to 8)
  - `no_repeats=True` produces no consecutive duplicates (50 iterations)
  - `min_characters_per_type` is honoured for each type (20 iterations)
  - Empty charset raises `ValueError`
- **Progressive strength scoring:**
  - 5 character types score >= 4 types
  - 4 character types score >= 3 types
  - Single character type is penalised

**How to run:**

```bash
pytest tests/test_generator.py -v
```

---

### `test_strength_pytest.py` -- 37 tests

**Module under test:** `secure_password_generator.generator` (strength
scoring, charset computation, expected-uniqueness formula)

This is the most comprehensive test file, organised into seven test
classes.

**What it covers:**

- **Consistency (zero flicker):**
  - 50 passwords generated with the blank+full config all score 10/10
  - 50 passwords generated with the full config (no blank) all score
    within the expected range {9, 10}
- **Entropy boundaries (parametrized):**
  - Six password/pool combinations verified against minimum expected
    scores (from 2 up to 10)
  - Short passwords (4 chars) score low
  - Long diverse passwords (33 chars, 5 types) score high
- **Character diversity:**
  - Single-type password is penalised (score <= 6)
  - Three types score higher than two
  - Five types with blank achieve score >= 9
  - Progressive: 5 types >= 4 types (explicit assertion)
- **Edge cases:**
  - Empty password returns 1
  - Single character returns 1
  - All-spaces password scores <= 2
  - `charset_size=None` infers the pool from the password characters
  - Score is always in range [1, 10] across diverse inputs
- **Expected-uniqueness formula (`expected_unique_chars`):**
  - Single draw from pool of 26 returns ~1.0
  - Large pool / small length returns near-length value
  - Small pool / large length saturates near pool size
  - Pool equals length returns a value between 15 and 26
  - Zero inputs return 0.0
  - Monotonically increasing in length
- **`compute_charset_size` sanity:**
  - Upper-only = 26, upper+lower = 52, all types = 94
  - `exclude_similar` reduces the pool
  - `blank` adds 1
  - Custom symbols produces exact count
  - Blank config pool > 50
- **`build_charset` sanity:**
  - Tuple sizes match `compute_charset_size`
  - All charsets are non-empty
  - `exclude_similar` reduces total characters
  - Blank config matches its computed pool

**How to run:**

```bash
pytest tests/test_strength_pytest.py -v
```

---

### `test_integration.sh` -- 52 tests

**Type:** Bash shell script (end-to-end CLI tests)

This script exercises the `pwgen` command as an end user would.  It
creates and destroys vault files in `~/.secure_passwords/` during
execution.  It can be run directly or sourced.

**What it covers, in order:**

| Tests  | Category                 | Description                                                                                                |
|:------:|--------------------------|------------------------------------------------------------------------------------------------------------|
| 0a--0b | Master-password setup    | Set master password, verify vault ops fail without it                                                      |
|  1--4  | Basic functionality      | Generation (no save), metadata, multiple passwords, passphrase                                             |
| 5--10  | Character types          | Upper-only, lower-only, digits-only (with output regex verification), symbols, custom symbols, blank       |
| 11--16 | Advanced options         | Exclude similar, no repeats, min per type, pattern, pattern+blank, multiple count                          |
| 17--25 | History viewing          | Table display, limit, search by label/category/tags, filter by category/strength/date, combined filters    |
| 26--27 | Entry management         | Authenticated delete (requires key), history after delete                                                  |
| 28--32 | Edge cases               | Minimum length enforcement, long (32) and very long (64) passwords, all options combined, wildcard pattern |
|   33   | Pattern minimum length   | Short pattern `"ld"` produces password >= 8 characters                                                     |
| 34--35 | File operations          | No-save flag verification, help message                                                                    |
| 36--40 | Config files             | YAML config, JSON config, missing config error, CLI override, `blank_space` key mapping                    |
| 41--42 | Master-password security | Correct password succeeds, wrong password produces no readable entries                                     |
| 43--44 | Alternative auth methods | `SPG_MASTER_PASSWORD` env-var, `--master-password-file`                                                    |
|   45   | System dependency        | `shred` binary is available                                                                                |
|   46   | Blank-position stress    | 100 iterations: blank never at first or last position                                                      |
|   47   | Package entry point      | `python -m secure_password_generator` works                                                                |
| 48--49 | Cleanup                  | Secure deletion, verify vault and salt are gone                                                            |
|   50   | Backward compatibility   | Vault without master password (file-key only) still works                                                  |

**How to run:**

```bash
bash tests/test_integration.sh
```

**Exit codes:** On failure the script exits with the test number (e.g.,
exit code 26 means Test 26 failed).  Exit code 0 means all tests passed.

---

### `benchmark_strength.py` -- diagnostic tool

**Type:** Standalone CLI script (not a pytest test)

**Purpose:** Generates N passwords per configuration and reports score
distributions, mean, standard deviation, and whether flicker (more than
one distinct score) was observed.  Useful for tuning the strength-scoring
algorithm or verifying that a change to the generator does not introduce
score instability.

**Bundled configurations:**

|       Key       | Description                             | Length | Pool |
|:---------------:|-----------------------------------------|:------:|:----:|
|  `blank_full`   | Full charset + blank + similar excluded |   33   |  65  |
| `full_no_blank` | Full charset, no blank                  |   24   |  94  |
| `short_simple`  | Upper + lower only                      |   10   |  52  |

**How to run:**

```bash
# Default: 100 iterations per config
python tests/benchmark_strength.py

# Custom iteration count
python tests/benchmark_strength.py -n 200

# Specific configs only
python tests/benchmark_strength.py -c blank_full short_simple
```

**Sample output:**

```text
======================================================================
  Config:      Full + Blank (blank-space config)
  Length:      33
  Pool size:   65
  Iterations:  100
======================================================================
  Strength scores:
    Score 10:  100 (100.0%) ##################################################
    Mean:   10.00
    StdDev: 0.000
    Range:  10 - 10

  Flicker (>1 distinct score): NO
```

---

## CI / Container Usage

Run the full test suite in an isolated Podman container:

```bash
podman run --rm -v $(pwd):/workspace:Z fedora:latest bash -c \
  "cd /workspace && dnf install -y python3 python3-pip > /dev/null 2>&1 \
  && pip3 install -e '.[dev]' > /dev/null 2>&1 \
  && pytest tests/ -v \
  && bash tests/test_integration.sh"
```
