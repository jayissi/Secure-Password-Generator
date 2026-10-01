# tests/ -- Test Suite Reference

This directory contains all automated tests for the Secure Password
Generator.  Every test runs through pytest -- there are no shell scripts
to invoke separately.

**Summary:**

|           File            |        Type         | Tests | Runtime |
|:-------------------------:|:-------------------:|:-----:|:-------:|
|     `test_config.py`      |    pytest (unit)    |  14   |  < 1s   |
|     `test_crypto.py`      |    pytest (unit)    |  16   |  < 1s   |
|    `test_generator.py`    |    pytest (unit)    |  19   |  < 1s   |
| `test_strength_pytest.py` |    pytest (unit)    |  37   |  < 1s   |
|     `test_history.py`     |   pytest (vault)    |  18   |  < 1s   |
|       `test_cli.py`       |    pytest (CLI)     |  19   |  < 1s   |
|  `test_entry_points.py`   | pytest (subprocess) |   3   |  < 1s   |
|         **Total**         |                     | **126** | **< 1s** |

---

## Prerequisites

Install the package in editable mode with development dependencies:

```bash
pip install -e '.[dev]'
```

System dependencies (`shred`, optionally `xclip`) should be available --
see `bindep.txt` in the project root.

---

## Quick Start

Run the entire suite with a single command:

```bash
pytest tests/ -v
```

The test-mode Argon2id profile (`SPG_TEST_KDF=1`) is applied automatically
by a module-level statement in `conftest.py`.  No environment variable
needs to be set manually.

Performance benchmarks live in the `benchmarks/` directory at the project
root -- see [benchmarks/README.md](../benchmarks/README.md).

---

## Test Architecture

### Speed

The suite runs in under 1 second.  Two optimisations make this possible:

1. **Test-mode Argon2id** -- a module-level `os.environ` call in
   `conftest.py` sets `SPG_TEST_KDF=1` before any package import, which
   reduces Argon2id from 100 iterations / 64 MiB to 1 iteration / 8 MiB.
   Production security is unchanged because the override only takes effect
   when the environment variable is set.

2. **In-process CLI calls** -- `test_cli.py` invokes `cli.main()` directly
   via the `run_cli()` helper in `conftest.py`, avoiding subprocess cold
   starts.  Only `test_entry_points.py` (3 tests) shells out to the real
   `pwgen` binary.

### Isolation

No test touches `~/.secure_passwords/`.  The `vault_dir` fixture in
`conftest.py` patches all path constants to a pytest `tmp_path` directory.
Each test gets a fresh, empty vault.

---

## File Reference

### `conftest.py` -- shared fixtures and helpers

- Module-level `os.environ["SPG_TEST_KDF"] = "1"` -- sets the test KDF
  override before any package import.
- `vault_dir(tmp_path)` -- function-scoped fixture that redirects all vault
  paths to a temp directory and clears crypto caches.
- `run_cli(*args)` -- helper that calls `cli.main()` in-process, captures
  stdout/stderr, and returns a `CLIResult` dataclass.

### `test_config.py` -- 14 tests

Module under test: `secure_password_generator.config`

- `load_config()` raises `ConfigError` for: missing file, unsupported
  extension, invalid YAML/JSON, non-dict YAML, unknown keys
- YAML and JSON round-trip (values read back correctly)
- `blank_space` key mapped to `blank`
- `CharsetConfig` dataclass: defaults, frozen, equality, hashable

### `test_crypto.py` -- 16 tests

Module under test: `secure_password_generator.crypto`

- Encrypt/decrypt round-trip (correct key, wrong key, short blob, empty)
- `combine_keys()` XOR identity, self-XOR, length mismatch
- Master-password complexity: too short, missing types, valid (3 and 4 types)
- `resolve_master_password()` priority: CLI flag > env-var > file > None

### `test_generator.py` -- 19 tests

Module under test: `secure_password_generator.generator`

- `build_charset` with empty, single, all types, custom symbols, exclude similar
- `compute_charset_size` minimum and blank offset
- Pattern minimum-length padding and long-pattern passthrough
- Blank never at first/last (100-iteration stress)
- `_filter_similar_chars` LRU cache identity
- `generate_password`: min length, no-repeats (50 iter), min-per-type (20 iter), empty charset
- Progressive scoring: 5 types >= 4 >= 3, single type penalised

### `test_strength_pytest.py` -- 37 tests

Module under test: `secure_password_generator.generator` (strength scoring)

- Consistency: stable scores under blank and full configs (50 iterations each)
- Entropy boundaries: 6 parametrised thresholds, short/long passwords
- Diversity bonuses: single-type penalty, two-types neutral, five-types max
- Edge cases: empty, single char, all spaces, inferred pool, range check
- Expected-uniqueness formula: single draw, saturation, monotonicity, zeros
- `compute_charset_size` / `build_charset` sanity checks

### `test_history.py` -- 18 tests

Module under test: `secure_password_generator.history`

- `save_password`: file creation, metadata round-trip, multiple entries
- `show_password_history`: empty vault, table format, search (label,
  category, tags), filter (strength, category, date), limit
- `delete_entry_by_index`: authenticated delete, wrong key rejected,
  invalid index, empty vault
- `format_history_table`: empty input, header presence

### `test_cli.py` -- 19 tests

Module under test: `secure_password_generator.cli` (via `run_cli()`)

- Master-password lifecycle: set, reject without, env-var auth, password-file
  auth, wrong password shows no entries
- Generation modes: `-F` full, `-c 3` multiple, `-P` passphrase, pattern,
  pattern with wildcard
- CLI plumbing: `-h` exits 0, no-args help, YAML config, JSON config, CLI
  override beats config, `--no-save-history`
- Cleanup: files removed, vault empty after
- No-master-password backward compat

### `test_entry_points.py` -- 3 tests

Subprocess smoke tests (the only file that shells out):

- `pwgen -F -L 12 -n` exits 0 and prints a password
- `python -m secure_password_generator -F -L 12 -n` exits 0
- `shred` binary is on `PATH`

---

> **Benchmarks** (generation throughput, crypto timing, scoring consistency)
> live in `benchmarks/` at the project root.
> See [benchmarks/README.md](../benchmarks/README.md).

---

## CI / Container Usage

Run the full suite in an isolated Podman container:

```bash
podman run --rm -v $(pwd):/workspace:Z fedora:latest bash -c \
  "cd /workspace && dnf install -y python3 python3-pip > /dev/null 2>&1 \
  && pip3 install -e '.[dev]' > /dev/null 2>&1 \
  && pytest tests/ -v"
```
