# 🔐 Secure Password Generator

[![RHEL 9+](https://img.shields.io/badge/RHEL-9+-ee0000?logo=redhat&logoColor=ee0000)](https://www.redhat.com/en/technologies/linux-platforms/enterprise-linux) <!-- https://www.redhat.com/en/about/brand/standards/color -->
[![Fedora 41+](https://img.shields.io/badge/Fedora-41+-51a2da?logo=fedora&logoColor=51a2da)](https://fedoraproject.org/) <!-- https://docs.fedoraproject.org/en-US/project/brand/#_colors -->
![Python Version](https://img.shields.io/badge/python-3.13+-306998?logo=python&logoColor=FFD43B&label=Python) <!-- https://brandpalettes.com/python-logo-colors -->
![License](https://img.shields.io/badge/license-MIT-750014?logo=open-source-initiative&logoColor=750014) <!-- https://brand.mit.edu/color -->
![Security](https://img.shields.io/badge/security-cryptographically_secure-008000?logo=lock&logoColor=008000)
![Interactive](https://img.shields.io/badge/mode-interactive-blue)
[![CI](https://github.com/jayissi/Secure-Password-Generator/actions/workflows/ci.yml/badge.svg)](https://github.com/jayissi/Secure-Password-Generator/actions/workflows/ci.yml)

A robust, powerful, and secure command-line utility for generating **cryptographically strong passwords**. Built with Python's `secrets` module, this tool supports Argon2id password hashing and Base64-encoded AES-GCM-SIV encryption with customizable character sets, password metadata organization, and advanced search capabilities.

<br/>

<p align="center">
<img alt="Python" src="https://www.python.org/static/community_logos/python-logo-master-v3-TM.png">
</p>

---

## ✨ Features

- **Cryptographically Secure** randomness via Python's `secrets` module
- **Two-Factor Encryption** — master password XOR'd with `encryption.key` via Argon2id + AES-GCM-SIV
- **Interactive Mode** — guided REPL with `quick`, `new`, `browse`, and `health` commands (`pwgen -i`)
- **Flexible Character Policies** — uppercase, lowercase, digits, symbols, blanks, Latin-1 Supplement, custom symbol sets, exclude similar, no repeats, minimum per-type
- **Pattern-Based Generation** — define exact character positions (`l`/`u`/`d`/`s`/`b`/`*`)
- **Password Strength Meter** — entropy-based 1–10 scoring with diversity bonuses and pattern penalties
- **Metadata & Organization** — labels, categories, comma-separated tags, automatic timestamps
- **History Management** — table view, search, filter by strength/category/date, authenticated deletion
- **Config File Support** — YAML or JSON defaults; CLI args always override
- **Clipboard Support** — copy via `pyperclip` with configurable auto-clear (default 60 s)
- **Master Password Security** — env-var, password file, or interactive prompt with complexity enforcement
- **Structured Logging** — `--verbose` / `--quiet` flags via Python `logging`

---

## 🚀 Getting Started

### 🔍 Prerequisites

**Python dependencies** are installed automatically by `pip` (see `pyproject.toml`):

|    Package     | Purpose                               |
|:--------------:|---------------------------------------|
| `argcomplete`  | Shell tab-completion                  |
| `cryptography` | AES-GCM-SIV encryption, Argon2id KDF  |
|  `pyperclip`   | Clipboard support                     |
|    `PyYAML`    | YAML config file support              |
|    `segno`     | QR code generation                    |
|   `tabulate`   | Formatted history table output        |
|   `textual`    | Graphical terminal UI (TUI)           |
|    `bandit`    | Security linter (dev dependency)      |
| `pymarkdownlnt`| Markdown linter (dev dependency)      |
|   `pyright`    | Static type checking (dev dependency) |
|    `pytest`    | Test suite (dev dependency)           |
| `pytest-asyncio`| Async test support for TUI (dev)     |
| `pytest-cov`   | Test coverage (dev dependency)        |
| `pytest-textual-snapshot` | Visual regression for TUI (dev) |
|     `ruff`     | Linter (dev dependency)               |

**System/RPM dependencies** are listed in `requirements-rpm.txt`:

|    Package    | Purpose                      | Required? |
|:-------------:|------------------------------|:---------:|
|  `coreutils`  | Provides `shred`             |    Yes    |
| `nodejs-npm`  | Required by pyright (dev)    | Optional  |

Install system dependencies on Fedora / RHEL:

```bash
dnf install coreutils
```

### 🛠️ Installation

1. Clone this repository:

    ```bash
    git clone https://github.com/jayissi/Secure-Password-Generator.git
    cd Secure-Password-Generator
    ```

2. Install the package:

    ```bash
    python -m pip install -e .
    ```

    This installs all Python dependencies and creates the `pwgen` command.

    For development, use a virtual environment:

    ```bash
    python -m venv .venv
    source .venv/bin/activate
    python -m pip install --upgrade pip
    python -m pip install -e . -r requirements-dev.txt
    ```

3. Verify installation:

    ```bash
    pwgen -h
    ```

> **Note:** If you previously had a `~/bin/pwgen` script, remove it to
> avoid shadowing the pip-installed entry point.

<br/>

That's it! You're ready to generate passwords.

---

## 📁 Project Structure

```text
Secure-Password-Generator/
├── .github/
│   ├── workflows/ci.yml              # CI: lint, test, smoke test
│   └── dependabot.yml                # Automated dependency updates
├── pyproject.toml                    # PEP 621 metadata and entry points
├── requirements.txt                  # Runtime Python dependencies
├── requirements-dev.txt              # Dev Python dependencies (linters, tests)
├── requirements-rpm.txt              # System/RPM dependencies
├── config-sample.yaml                # Example YAML config
├── config-example.json               # Example JSON config
├── docs/                             # Detailed documentation
│   ├── EXAMPLES.md                   # Comprehensive usage examples
│   ├── INTERACTIVE.md                # Interactive mode guide
│   ├── SECURITY.md                   # Encryption flow and threat model
│   └── CONFIGURATION.md             # Config file format and fields
├── secure_password_generator/        # Main package
│   ├── __init__.py                   # Version, public API, __all__
│   ├── py.typed                      # PEP 561 type-checking marker
│   ├── __main__.py                   # python -m support
│   ├── constants.py                  # All constants and defaults
│   ├── config.py                     # CharsetConfig dataclass, config loader
│   ├── crypto.py                     # Encryption, key mgmt, Argon2id
│   ├── generator.py                  # Password generation, strength scoring
│   ├── history.py                    # Vault CRUD, table formatting
│   ├── clipboard.py                  # Clipboard operations
│   ├── qrcode.py                     # QR code generation (segno)
│   ├── tui.py                        # Textual TUI application
│   ├── tui.tcss                      # TUI stylesheet
│   ├── utils.py                      # Secure deletion, file permissions, logging
│   ├── interactive.py                # Interactive REPL (PwgenShell)
│   └── cli.py                        # Argument parser, main()
├── tests/
│   ├── conftest.py                   # Shared fixtures (vault_dir, run_cli)
│   ├── test_config.py                # Config loader tests
│   ├── test_crypto.py                # Crypto module tests
│   ├── test_generator.py             # Generator module tests
│   ├── test_strength_pytest.py       # Strength scoring pytest suite
│   ├── test_history.py               # Vault CRUD tests
│   ├── test_utils.py                 # Utils module tests
│   ├── test_interactive.py           # Interactive mode tests
│   ├── test_cli.py                   # CLI integration tests (in-process)
│   ├── test_clipboard.py             # Clipboard module tests
│   ├── test_qrcode.py                # QR code module tests
│   ├── test_tui.py                   # Textual TUI tests
│   └── test_entry_points.py          # Subprocess smoke tests
└── benchmarks/                       # Performance diagnostic tools
    ├── benchmark_strength.py         # Scoring consistency
    ├── benchmark_generation.py       # Generation throughput
    └── benchmark_crypto.py           # Crypto operation timing
```

---

## 💻 Usage

Run the `pwgen` command with your desired options.
If you run `pwgen` with no arguments or with `-h`, it displays the help menu.

```bash
pwgen -h
```

You can also invoke via the Python module:

```bash
python -m secure_password_generator -h
```

### ⚙️ Command-Line Arguments

#### Basic Options

|         Argument         | Short | Description                                   | Default |
|:------------------------:|:-----:|-----------------------------------------------|:-------:|
|        `--length`        | `-L`  | Password length (min: 8)                      |   12    |
|        `--count`         | `-c`  | Number of passwords to generate               |    1    |
|      `--passphrase`      | `-P`  | Custom passphrase (supersedes other options)  |  None   |
|        `--config`        | `-f`  | Load defaults from YAML/JSON config file      |  None   |
|      `--clipboard`       | `-X`  | Copy password to clipboard (auto-clears)      |  False  |
|          `--qr`          | `-q`  | Display password as QR code in terminal       |  False  |
|       `--qr-file`        |       | Save password QR code to a PNG file           |  None   |
|     `--interactive`      | `-i`  | Start interactive mode (guided prompts)       |  False  |
|         `--tui`          | `-t`  | Start graphical terminal UI                   |  False  |
|        `--unlock`        | `-U`  | Explicitly unlock vault with master password  |  False  |
|   `--master-password`    |       | Master password for scripting/CI              |  None   |
| `--master-password-file` |       | Read master password from file (first line)   |  None   |
| `--set-master-password`  |       | Configure/change master password + re-encrypt |  False  |
|       `--verbose`        | `-v`  | Enable debug output                           |  False  |
|        `--quiet`         |       | Suppress warnings                             |  False  |
|         `--help`         | `-h`  | Show help message                             |   N/A   |
|       `--version`        | `-V`  | Show version and exit                         |   N/A   |

#### Character Type Options

|      Argument       | Short | Description                                | Default |
|:-------------------:|:-----:|--------------------------------------------|:-------:|
|      `--full`       | `-F`  | Use all character types + no-repeats       |  False  |
|      `--upper`      | `-u`  | Include uppercase letters                  |  False  |
|      `--lower`      | `-l`  | Include lowercase letters                  |  False  |
|     `--digits`      | `-d`  | Include digits                             |  False  |
|     `--symbols`     | `-s`  | Include symbols                            |  False  |
| `--allowed-symbols` | `-a`  | Custom allowed symbols (implies --symbols) |  None   |
|      `--blank`      | `-b`  | Include space (never first/last)           |  False  |
|    `--latin-ext`    | `-x`  | Include Latin-1 Supplement characters      |  False  |
|     `--pattern`     | `-p`  | Pattern string (l/u/d/s/b/x/* codes)       |  None   |

#### Advanced Options

|      Argument       | Short | Description                    | Default |
|:-------------------:|:-----:|--------------------------------|:-------:|
|       `--min`       | `-m`  | Min chars per selected type    |    1    |
|   `--no-repeats`    | `-r`  | No consecutive duplicate chars |  False  |
| `--exclude-similar` | `-e`  | Exclude similar-looking chars  |  False  |

#### Password Organization Options

|   Argument   | Description                  | Default |
|:------------:|------------------------------|:-------:|
|  `--label`   | Label/name for this password | Unnamed |
| `--category` | Category for this password   | General |
|   `--tags`   | Comma-separated tags         |   []    |

#### History Search & Filter Options

|      Argument       | Description                                    |
|:-------------------:|------------------------------------------------|
|     `--search`      | Search history by label, category, or tags     |
| `--filter-strength` | Show only passwords with strength >= value     |
| `--filter-category` | Show only passwords in this category           |
|      `--since`      | Show passwords since date (YYYY-MM-DD)         |
|  `--delete-entry`   | Delete specific entry by index (authenticated) |
|      `--limit`      | Limit number of history entries to display     |

#### File Operations

|      Argument       | Short | Description                      | Default |
|:-------------------:|:-----:|----------------------------------|:-------:|
| `--no-save-history` | `-n`  | Don't save to password history   |  False  |
|  `--show-history`   | `-H`  | Show password generation history |  False  |
|     `--cleanup`     | `-C`  | Clean up password and key files  |  False  |

---

## 📝 Quick Start Examples

Generate a strong password (don't save):

```bash
pwgen -F -L 20 -n
```

Generate and save with metadata:

```bash
pwgen -F -L 16 --label "Gmail" --category "Email" --tags "work"
```

Generate and display as QR code:

```bash
pwgen -F -L 20 -n -q
```

View saved passwords:

```bash
pwgen -H
```

Start interactive mode:

```bash
pwgen -i
```

Start the graphical terminal UI:

```bash
pwgen -t
```

For a full tutorial and recipes, see [docs/EXAMPLES.md](docs/EXAMPLES.md).

---

## 📚 Documentation

| Document                                 | Description                                |
|------------------------------------------|--------------------------------------------|
| [Examples](docs/EXAMPLES.md)             | Detailed usage examples with sample output |
| [Interactive Mode](docs/INTERACTIVE.md)  | Guided interactive interface               |
| [Configuration](docs/CONFIGURATION.md)   | YAML/JSON config file format               |
| [Security](docs/SECURITY.md)             | Encryption flow, storage, threat model     |

---

## 🧪 Testing

The test suite runs through pytest in under 2 seconds with automatic coverage reporting. A test-mode Argon2id profile is applied automatically by `conftest.py`. Static type checking (pyright), security scanning (bandit), and markdown linting (pymarkdownlnt) run alongside ruff.

|           File            | Tests | Coverage                                                   |
|:-------------------------:|:-----:|------------------------------------------------------------|
|     `test_config.py`      |  14   | Config loading, CharsetConfig, ConfigError                 |
|     `test_crypto.py`      |  44   | Encrypt/decrypt, key mgmt, master-password, argon2id, temp file, caching |
|    `test_generator.py`    |  35   | Charset, constraints, scoring, latin-ext, NFC, symbol-only |
| `test_strength_pytest.py` |  43   | Entropy boundaries, consistency, edge cases                |
|     `test_history.py`     |  35   | Vault CRUD, search/filter, delete, TOCTOU, dedup, NFC      |
|      `test_utils.py`      |  11   | File permissions, logging, vault lock, secure delete       |
|   `test_interactive.py`   | 123   | Interactive commands, browse, health, generate, QR, edge cases |
|       `test_cli.py`       |  48   | CLI integration, master-password, clipboard, QR, edge cases |
|   `test_clipboard.py`     |   7   | Clipboard copy, failure, timer cancel, clear callback      |
|    `test_qrcode.py`       |   3   | QR code display, save, custom scale                        |
|      `test_tui.py`        |  74   | TUI app, modals, history actions, config, auth, tab switch |
|  `test_entry_points.py`   |   4   | Subprocess smoke tests, `__main__` module                  |

```bash
# Build the virtual environment
python -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e . -r requirements-dev.txt

# Run the linters, tests, and smoke test
bash << 'EOF'
set -e

echo '=== Ruff Lint ==='
ruff check secure_password_generator/ tests/ benchmarks/

echo '=== Pyright ==='
pyright secure_password_generator/ tests/

echo '=== Bandit ==='
bandit -r secure_password_generator/ -c pyproject.toml

echo '=== Markdown Lint ==='
pymarkdown --config .pymarkdown.json scan '**/*.md'

echo '=== Pytest ==='
pytest tests/ -v --tb=short

echo '=== Smoke Test ==='
pwgen -V
pwgen -F -L 16 -n
pwgen -F -x -L 20 -n

echo '=== ALL CHECKS PASSED ==='
EOF

# Exit the virtual environment
deactivate
```

See [tests/README.md](tests/README.md) for the full test architecture and
[benchmarks/README.md](benchmarks/README.md) for performance diagnostics.

---

## 🤝 Contributing

Contributions are welcome! Please open an issue or pull request for any improvements.

---

## 📜 License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for more details.
