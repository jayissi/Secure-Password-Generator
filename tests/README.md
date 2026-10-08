# tests/ -- Test Suite Reference

> Back to [main README](../README.md)

This directory contains all automated tests for the Secure Password
Generator.  Every test runs through pytest -- there are no shell scripts
to invoke separately.

**Summary:**

|           File            |        Type         |  Tests  |  Runtime  |
|:-------------------------:|:-------------------:|:-------:|:---------:|
|     `test_config.py`      |    pytest (unit)    |   19    |  < 1s     |
|     `test_crypto.py`      |    pytest (unit)    |   44    |  < 1s     |
|    `test_generator.py`    |    pytest (unit)    |   41    |  < 1s     |
| `test_strength_pytest.py` |    pytest (unit)    |   43    |  < 1s     |
|     `test_history.py`     |   pytest (vault)    |   35    |  < 1s     |
|      `test_utils.py`      |    pytest (unit)    |   11    |  < 1s     |
|   `test_interactive.py`   |  pytest (unit/CLI)  |  123    |  < 1s     |
|       `test_cli.py`       |    pytest (CLI)     |   52    |  < 1s     |
|   `test_clipboard.py`     |    pytest (unit)    |    7    |  < 1s     |
|    `test_qrcode.py`       |    pytest (unit)    |    3    |  < 1s     |
|      `test_tui.py`        |   pytest (async)    |   74    | < 30s     |
|  `test_entry_points.py`   | pytest (subprocess) |    4    |  < 1s     |
|         **Total**         |                     | **456** | **< 35s** |

---

## Prerequisites

Set up a virtual environment with development dependencies:

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e . -r requirements-dev.txt
```

System dependencies (`shred`) should be available -- see
`requirements-rpm.txt` in the project root.

### Key dev dependencies

| Package | Purpose |
|:-------:|---------|
| `pytest` | Test runner |
| `pytest-asyncio` | Async test support for Textual TUI tests (`App.run_test()`) |
| `pytest-cov` | Coverage reporting (`--cov` flag) |
| `pytest-textual-snapshot` | Visual regression testing for Textual apps |
| `ruff` | Linter and formatter |
| `pyright` | Static type checking |
| `bandit` | Security linter |
| `pymarkdownlnt` | Markdown linter |

### Snapshot testing

`pytest-textual-snapshot` provides visual regression testing for the
Textual TUI.  To update snapshot baselines after intentional UI changes:

```bash
pytest tests/test_tui.py --snapshot-update
```

TUI tests use Textual's headless `App.run_test()` API with
`pytest-asyncio` for async support.  No display server is required.

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

### `test_config.py` -- 19 tests

Module under test: `secure_password_generator.config`

- `load_config()` raises `ConfigError` for: missing file, unsupported
  extension, invalid YAML/JSON, non-dict YAML, unknown keys
- YAML and JSON round-trip (values read back correctly)
- `blank_space` key mapped to `blank`
- New config keys accepted: pattern, count, clipboard, qr, qr\_file
- `CharsetConfig` dataclass: defaults, frozen, equality, hashable

### `test_crypto.py` -- 44 tests

Module under test: `secure_password_generator.crypto`

- `TestEncryptDecrypt`: round-trip, wrong key, short blob, empty, AAD
- `TestCombineKeys`: XOR identity, self-XOR, length mismatch
- `TestMasterPasswordValidation`: too short, missing types, valid
- `TestResolveMasterPassword`: CLI flag > env-var > file > None
- `TestArgon2idHash`: return structure, unique salts
- `TestSetMasterPassword`: explicit, re-encryption, empty raises
- `TestCleanupFiles`: error handling, temp file removal, lock file,
  files\_initialized reset, already-clean vault
- `TestInitCaching`: flag set, skip on repeat call
- `TestMasterPasswordEdgeCases`: empty, only-lower, only-two-types
- `TestPromptMasterPassword`: non-TTY raises, empty input raises
- `TestGetEncryptionKey`: no-master key, master required, session cache
- `TestResolveMasterPasswordEdge`: file not found, file empty, interactive
- `TestSetMasterTempFile`: temp cleanup on failure, change master password

### `test_generator.py` -- 41 tests

Module under test: `secure_password_generator.generator`

- `build_charset` with empty, single, all types, custom symbols, exclude similar, latin_ext
- `compute_charset_size` minimum and blank offset, latin_ext adds 93
- Pattern minimum-length padding and long-pattern passthrough
- Pattern blank position: first/last/both raises, interior OK
- Pattern empty string raises ValueError
- Pattern min\_chars > 1 emits warning (caplog)
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

### `test_history.py` -- 35 tests

Module under test: `secure_password_generator.history`

- `TestSavePassword`: file creation, metadata round-trip, multiple entries
- `TestShowHistory`: empty vault, table format, search (label, category,
  tags), filter (strength, category, date), limit
- `TestDeleteEntry`: authenticated delete, wrong key rejected
- `TestUpdateEntryMetadata`: update label, preserves other fields
- `TestFormatHistoryTable`: empty input, header presence, coloured scores
- `TestCorruptEntryHandling`: corrupt skipped, valid shown, all corrupt
- `TestDeleteEntryTOCTOU`: missing vault, invalid index (inside lock)
- `TestUpdateEntryTOCTOU`: missing vault, invalid index (inside lock)
- `TestShowHistoryDedup`: delegates to get\_decrypted\_entries, non-table
  mode, no vault file
- `TestNFCSaveNormalization`: combining characters normalized

### `test_utils.py` -- 11 tests

Module under test: `secure_password_generator.utils`

- `verify_file_permissions()`: warns on insecure (0644) permissions, silent
  on correct (0600), no error on nonexistent path
- `configure_logging()`: verbose sets DEBUG, quiet sets ERROR

### `test_interactive.py` -- 123 tests

Module under test: `secure_password_generator.interactive`

- `TestQuickCommand`: default length, custom length, regenerate, score
- `TestNewCommand`: defaults wizard, custom length, save, cancel
- `TestBrowseCommand`: empty vault, populated, view entry detail
- `TestHealthCommand`: empty vault, populated with score distribution
- `TestSessionLifecycle`: quit, help, unknown command, EOF, clear,
  interactive flag, exit alias, emptyline
- `TestGenerateCommand`: full charset, multi-count, save prompt, batch
  save, copy, regenerate, no-save, metadata flags
- `TestHistoryCommand`: empty, populated, search, limit
- `TestDeleteCommand`: delete entry, missing arg, invalid index
- `TestCleanupCommand`: confirmed, cancelled, EOF
- `TestLabelCommand`: update metadata, invalid index, no args
- `TestBrowseExtended`: pagination, search, invalid entry, view copy,
  EOF, view number prompt, last/first page
- `TestHealthExtended`: weak warning, duplicate labels
- `TestQuickExtended`: copy, save, EOF, invalid then quit
- `TestGenerateExtended`: save batch EOF, batch copy multi
- `TestQRCodeInteractive`: quick QR, generate QR, batch QR, browse QR
- `TestPreloop`: no-master, master auth fail
- `TestGenerateBatchPrompt`: copy batch, copy fail, regenerate, invalid,
  EOF, no-save
- `TestSaveBatch`: with flags, EOF
- `TestBrowseEdge`: invalid number, NaN, previous/next page, search,
  search no match, invalid choice, EOF, view entry copy/fail/invalid/EOF
- `TestCleanupCommandEdge`: confirm, cancel, EOF
- `TestClearCommand`: ANSI escape output
- `TestLabelCommandEdge`: update, invalid index, no args
- `TestDeleteCommandEdge`: no arg, invalid, delete entry
- `TestHistoryCommandEdge`: search, empty
- `TestQuickEdgeCases`: save, regenerate, copy, copy fail, invalid
- `TestNewEdgeCases`: no charset selected
- `TestGenerateAllowedSymbols`, `TestGenerateWithAllowedSymbols`
- `TestViewEntryClipboardFail`, `TestBrowseKeyError`,
  `TestHealthKeyError`, `TestQuickSaveError`, `TestNewWizardEOF`,
  `TestViewEntryEOF`, `TestViewEntryNumberInput`,
  `TestBrowseSearchEOF`, `TestHistoryCommandError`,
  `TestDeleteCommandError`, `TestLabelCommandError`

### `test_cli.py` -- 52 tests

Module under test: `secure_password_generator.cli` (via `run_cli()`)

- `TestMasterPassword`: set, reject without, env-var, password-file, wrong
- `TestGenerationModes`: `-F` full, `-c 3` multi, `-P` passphrase, pattern
- `TestCLIPlumbing`: `-h`, no-args, YAML/JSON config, CLI override,
  `--no-save-history`, config pattern, config blank pattern fallback,
  config count, config QR (mocked)
- `TestCleanup`: files removed, vault empty after
- `TestNoMasterPassword`: backward compat
- `TestLatinExtCLI`: `-x -l` non-ASCII, `-F -x` combined
- `TestStrengthDisplay`: inline score, multi-count, meter bar
- `TestInteractiveFlag`: `-i` flag parsed
- `TestCLIEdgeCases`: `--version`, `--delete-entry`, passphrase save,
  history search
- `TestCLIConfigError`: invalid config, missing config
- `TestCLIClipboard`: `-X` success (mocked), unavailable (mocked)
- `TestCLIQRCode`: `-q` flag, `--qr-file`, multi-count indexed files
- `TestCLISetMasterPassword`: set-master error
- `TestCLIHistoryEdgeCases`: empty history, empty delete, QR mode, QR empty
- `TestCLIPassphrase`: no-save, with tags, generation error
- `TestCLITUIFlag`: `-t` flag parsed
- `TestCLIAllowedSymbols`: `--allowed-symbols` enables symbols
- `TestCLIHistoryQREdge`: QR with empty history

### `test_clipboard.py` -- 7 tests

Module under test: `secure_password_generator.clipboard`

- `TestCopyToClipboard`: success (mocked), failure (PyperclipException)
- `TestScheduleClipboardClear`: timer starts, previous timer cancelled,
  no cancel when no previous, clear callback calls pyperclip.copy(""),
  clear callback suppresses PyperclipException

### `test_qrcode.py` -- 3 tests

Module under test: `secure_password_generator.qrcode`

- `display_qr()` calls segno.make().terminal(compact=True)
- `save_qr()` calls segno.make().save() with path and scale
- `save_qr()` custom scale parameter

### `test_tui.py` -- 74 tests

Module under test: `secure_password_generator.tui`

Uses Textual's headless `App.run_test()` with `pytest-asyncio`:

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
- `TestHistoryActions`: reveal toggle, copy/qr/delete no selection,
  search submit
- `TestStatusReport`: weak warning output
- `TestConfigPaneActions`: refresh, cleanup confirm/cancel, set-master
  empty/mismatch/success
- `TestTabSwitching`: g/h/s/c key bindings
- `TestHelperFunctions`: \_strength\_color, \_escape\_markup
- `TestSaveModal`: cancel preserves passwords, escape
- `TestGenerateEdgeCases`: copy/qr/save with no password
- `TestRequireKey`: cached key, readonly no vault
- `TestMasterPasswordModal`: unlock, cancel, wrong password, input
  submit, escape
- `TestQRModal`: close button, escape
- `TestHistoryPaneDetailed`: copy success/fail, QR, delete with confirm
- `TestStatusPaneDetailed`: build report output
- `TestConfigSetMasterChange`: change master, no current password
- `TestGenerateError`: error display, default int val
- `TestRefreshOnTabSwitch`: tab activated refreshes
- `TestQuitBinding`: Q key exits

### `test_entry_points.py` -- 4 tests

Subprocess smoke tests and module entry point:

- `TestEntryPoints`: `pwgen -F -L 12 -n` exits 0, `python -m` exits 0
- `TestDunderMain`: `__main__.py` invokes `cli.main()`
- `TestSystemDependencies`: `shred` binary is on `PATH`

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
    python -m pip install --upgrade pip >/dev/null 2>&1
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
    pwgen -F -x -L 20 -n

    echo "=== ALL CHECKS PASSED ==="
  '
```

> **Note:** `nodejs-npm` is required because `pyright` is a Node.js binary.
> The `python -m pip install pyright` wrapper downloads Node automatically in most
> environments, but Fedora containers may not have `node` pre-installed.
> See `requirements-rpm.txt` for all system dependencies.
