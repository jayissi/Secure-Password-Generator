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
- **Clipboard Support** — copy via `pyperclip` or `xclip` with configurable auto-clear (default 60 s)
- **Master Password Security** — env-var, password file, or interactive prompt with complexity enforcement
- **Structured Logging** — `--verbose` / `--quiet` flags via Python `logging`

---

## 🚀 Getting Started

### 🔍 Prerequisites

**Python dependencies** are installed automatically by `pip` (see `pyproject.toml`):

|    Package     | Purpose                              |
|:--------------:|--------------------------------------|
| `argcomplete`  | Shell tab-completion                 |
| `cryptography` | AES-GCM-SIV encryption, Argon2id KDF |
|  `pyperclip`   | Clipboard support                    |
|    `PyYAML`    | YAML config file support             |
|   `tabulate`   | Formatted history table output       |
|    `pytest`    | Test suite (dev dependency)          |

**System/RPM dependencies** are listed in `requirements-rpm.txt`:

|   Package   | Purpose            | Required? |
|:-----------:|--------------------|:---------:|
| `coreutils` | Provides `shred`   |    Yes    |
|   `xclip`   | Clipboard fallback | Optional  |

Install system dependencies on Fedora / RHEL:

```bash
dnf install coreutils xclip
```

### 🛠️ Installation

1. Clone this repository:

    ```bash
    git clone https://github.com/jayissi/Secure-Password-Generator.git
    cd Secure-Password-Generator
    ```

2. Install the package (editable mode recommended for development):

    ```bash
    pip install -e .
    ```

    This installs all Python dependencies and creates the `pwgen` command.

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
├── requirements.txt                  # pip install -r compatibility
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
|     `--interactive`      | `-i`  | Start interactive mode (guided prompts)       |  False  |
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
|     `--pattern`     | `-p`  | Pattern string (l/u/d/s/b/* codes)         |  None   |

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

View saved passwords:

```bash
pwgen -H
```

Start interactive mode:

```bash
pwgen -i
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

The test suite runs through pytest in under 2 seconds. A test-mode Argon2id profile is applied automatically by `conftest.py`.

|           File            | Tests | Coverage                                                   |
|:-------------------------:|:-----:|------------------------------------------------------------|
|     `test_config.py`      |  14   | Config loading, CharsetConfig, ConfigError                 |
|     `test_crypto.py`      |  18   | Encrypt/decrypt, key management, master-password, argon2id |
|    `test_generator.py`    |  35   | Charset, constraints, scoring, latin-ext, NFC, symbol-only |
| `test_strength_pytest.py` |  41   | Entropy boundaries, consistency, edge cases                |
|     `test_history.py`     |  25   | Vault CRUD, search/filter, delete, metadata, NFC save      |
|      `test_utils.py`      |   5   | File permissions, logging configuration                    |
|   `test_interactive.py`   |  43   | Interactive commands, session lifecycle, label             |
|       `test_cli.py`       |  29   | CLI integration, latin-ext, strength display, edge cases   |
|  `test_entry_points.py`   |   3   | Subprocess smoke tests for pwgen and python -m             |

```bash
pytest tests/ -v
```

See [tests/README.md](tests/README.md) for the full test architecture and
[benchmarks/README.md](benchmarks/README.md) for performance diagnostics.

---

## 🤝 Contributing

Contributions are welcome! Please open an issue or pull request for any improvements.

---

## 📜 License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for more details.
