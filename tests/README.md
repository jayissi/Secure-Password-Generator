# tests/ -- Test Suite Reference

> Back to [main README](../README.md)

This directory contains all automated tests for the Secure Password
Generator.  Every test runs through pytest -- there are no shell scripts
to invoke separately.

**Summary:**

|           File            |        Type         |  Tests  | Runtime  |
|:-------------------------:|:-------------------:|:-------:|:--------:|
|     `test_config.py`      |    pytest (unit)    |   14    |  < 1s    |
|     `test_crypto.py`      |    pytest (unit)    |   25    |  < 1s    |
|    `test_generator.py`    |    pytest (unit)    |   35    |  < 1s    |
| `test_strength_pytest.py` |    pytest (unit)    |   43    |  < 1s    |
|     `test_history.py`     |   pytest (vault)    |   27    |  < 1s    |
|      `test_utils.py`      |    pytest (unit)    |   11    |  < 1s    |
|   `test_interactive.py`   |  pytest (unit/CLI)  |   71    |  < 1s    |
|       `test_cli.py`       |    pytest (CLI)     |   36    |  < 1s    |
|   `test_clipboard.py`     |    pytest (unit)    |    3    |  < 1s    |
|    `test_qrcode.py`       |    pytest (unit)    |    3    |  < 1s    |
|      `test_tui.py`        |   pytest (async)    |   27    |  < 9s    |
|  `test_entry_points.py`   | pytest (subprocess) |    3    |  < 1s    |
|         **Total**         |                     | **298** | **< 15s** |

---

## Prerequisites

Set up a virtual environment with development dependencies:

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install -e . -r requirements-dev.txt
```

System dependencies (`shred`) should be available -- see
`requirements-rpm.txt` in the project root.

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

### `test_crypto.py` -- 25 tests

Module under test: `secure_password_generator.crypto`

- Encrypt/decrypt round-trip (correct key, wrong key, short blob, empty)
- AAD: mismatched AAD raises InvalidTag, None AAD round-trip
- `combine_keys()` XOR identity, self-XOR, length mismatch
- Master-password complexity: too short, missing types, valid (3 and 4 types)
- `resolve_master_password()` priority: CLI flag > env-var > file > None
- `argon2id_hash()` return structure and unique salts
- `set_master_password()` explicit, re-encryption, empty raises
- `cleanup_files()` error handling (mocked secure_delete_file)

### `test_generator.py` -- 35 tests

Module under test: `secure_password_generator.generator`

- `build_charset` with empty, single, all types, custom symbols, exclude similar, latin_ext
- `compute_charset_size` minimum and blank offset, latin_ext adds 93
- Pattern minimum-length padding and long-pattern passthrough
- Blank never at first/last (100-iteration stress)
- `_filter_similar_chars` LRU cache identity
- `generate_password`: min length, no-repeats (50 iter), min-per-type (20 iter), empty charset
- Progressive scoring: 5 types >= 4 >= 3, single type penalised
- Latin-ext: build_charset includes latin_ext tuple, chars in range, non-ASCII in output, no-repeats, min-per-type
- Symbol-only generation: no consecutive repeats, single symbol raises
- NFC normalization: generate_password and pattern output are NFC-normalized

### `test_strength_pytest.py` -- 43 tests

Module under test: `secure_password_generator.generator` (strength scoring)

- Consistency: stable scores under blank and full configs (50 iterations each)
- Entropy boundaries: 6 parametrised thresholds, short/long passwords
- Diversity bonuses: single-type penalty, two-types neutral, five-types max
- Edge cases: empty, single char, all spaces, inferred pool, range check
- Expected-uniqueness formula: single draw, saturation, monotonicity, zeros
- `compute_charset_size` / `build_charset` sanity checks
- Latin-ext scoring: 6-type beats 5-type, latin-ext-only no crash, pool inference adds 93, 5-type regression check

### `test_history.py` -- 27 tests

Module under test: `secure_password_generator.history`

- `save_password`: file creation, metadata round-trip, multiple entries
- `show_password_history`: empty vault, table format, search (label,
  category, tags), filter (strength, category, date), limit
- `delete_entry_by_index`: authenticated delete, wrong key rejected,
  invalid index, empty vault
- `update_entry_metadata`: update label, preserves other fields,
  invalid index, empty vault
- `format_history_table`: empty input, header presence, coloured strength
  scores, timestamp format
- NFC save normalization: combining characters normalized before storage

### `test_utils.py` -- 11 tests

Module under test: `secure_password_generator.utils`

- `verify_file_permissions()`: warns on insecure (0644) permissions, silent
  on correct (0600), no error on nonexistent path
- `configure_logging()`: verbose sets DEBUG, quiet sets ERROR

### `test_interactive.py` -- 71 tests

Module under test: `secure_password_generator.interactive`

- `TestQuickCommand`: default length, custom length, regenerate prompt,
  inline score in output
- `TestNewCommand`: all-defaults wizard, custom length, save with label,
  cancel without save
- `TestBrowseCommand`: empty vault message, populated vault shows entries,
  view entry detail
- `TestHealthCommand`: empty vault report, populated vault with score
  distribution
- `TestSessionLifecycle`: quit exits, help lists commands, unknown command
  shows error, EOF exits, clear does not crash, interactive flag accepted,
  exit alias returns True, emptyline no-op
- `TestGenerateCommand`: full charset, multi-count with summary, sets
  last password, invalid flag, quick sets last password, save prompt,
  batch save, copy prompt, regenerate prompt, no-save flag skips prompt,
  batch display, save clears state, metadata flags
- `TestHistoryCommand`: empty vault, populated vault, search, limit
- `TestDeleteCommand`: delete entry, missing arg, invalid index
- `TestCleanupCommand`: confirmed, cancelled, EOF cancellation
- `TestLabelCommand`: label updates metadata, invalid index, no args,
  generate with metadata
- `TestBrowseExtended`: pagination next/prev, search, invalid entry,
  view copy back, EOF, invalid choice, view number prompt, search no
  match, already last/first page, invalid view number
- `TestHealthExtended`: weak password warning, duplicate labels
- `TestQuickExtended`: copy, save, EOF, invalid then quit
- `TestGenerateExtended`: save batch EOF, batch copy multi
- `TestQRCodeInteractive`: quick QR, generate QR, batch QR, browse
  view QR

### `test_cli.py` -- 36 tests

Module under test: `secure_password_generator.cli` (via `run_cli()`)

- Master-password lifecycle: set, reject without, env-var auth, password-file
  auth, wrong password shows no entries
- Generation modes: `-F` full, `-c 3` multiple, `-P` passphrase, pattern,
  pattern with wildcard
- CLI plumbing: `-h` exits 0, no-args help, YAML config, JSON config, CLI
  override beats config, `--no-save-history`
- Cleanup: files removed, vault empty after
- No-master-password backward compat
- Latin-ext: `-x -l` produces non-ASCII, `-F -x` combined works
- CLI edge cases: `--version` flag, `--delete-entry` integration,
  passphrase save mode, history search filter
- Config error: invalid config file, missing config file
- Clipboard: `-X` flag success (mocked), clipboard unavailable (mocked)
- QR code: `-q` flag (mocked), `--qr-file` file creation, multi-count
  indexed files

### `test_clipboard.py` -- 3 tests

Module under test: `secure_password_generator.clipboard`

- `copy_to_clipboard()` success (mocked pyperclip.copy)
- `copy_to_clipboard()` failure (mocked PyperclipException)
- `schedule_clipboard_clear()` timer starts (mocked threading.Timer)

### `test_qrcode.py` -- 3 tests

Module under test: `secure_password_generator.qrcode`

- `display_qr()` calls segno.make().terminal(compact=True)
- `save_qr()` calls segno.make().save() with path and scale
- `save_qr()` custom scale parameter

### `test_tui.py` -- 27 tests

Module under test: `secure_password_generator.tui`

Uses Textual's headless `App.run_test()` for async testing:

- `TestAppStartup`: app composes, 4 tabs exist, footer visible
- `TestGeneratePane`: generate button, count, copy, QR, save modal,
  output cleared after save, allowed symbols, min chars
- `TestHistoryPane`: refresh populated, empty vault guard (no files)
- `TestStatusPane`: load report, empty vault, vault guard (no files)
- `TestConfigPane`: info display
- `TestStartupAuth`: no modal without master password
- `TestEventDrivenRefresh`: save auto-refreshes history
- `TestStructuredSearch`: parse label, category, tags, strength,
  combined, empty, plain text
- `TestQuitBinding`: Q key exits

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

Run the full CI pipeline locally in a Podman container.  This mirrors the
GitHub Actions workflow (`.github/workflows/ci.yml`):

```bash
podman run --rm \
  -v "$(pwd):/workspace:Z" \
  fedora:latest \
  bash -e -c '
    cd /workspace

    dnf install -y python3 python3-pip nodejs-npm >/dev/null 2>&1
    python -m pip install -e . -r requirements-dev.txt >/dev/null 2>&1

    echo "=== Ruff Lint ==="
    ruff check secure_password_generator/ tests/ benchmarks/

    echo "=== Pyright ==="
    pyright secure_password_generator/ tests/

    echo "=== Bandit ==="
    bandit -r secure_password_generator/ -c pyproject.toml

    echo "=== Markdown Lint ==="
    pymarkdown --config .pymarkdown.json scan '\''**/*.md'\''

    echo "=== Pytest ==="
    pytest tests/ -v --tb=short

    echo "=== Smoke Test ==="
    pwgen -V
    pwgen -F -L 16 -n

    echo "=== ALL CHECKS PASSED ==="
  '
```

> **Note:** `nodejs-npm` is required because `pyright` is a Node.js binary.
> The `python -m pip install pyright` wrapper downloads Node automatically in most
> environments, but Fedora containers may not have `node` pre-installed.
> See `requirements-rpm.txt` for all system dependencies.
