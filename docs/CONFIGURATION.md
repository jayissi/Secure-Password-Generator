# ⚙️ Configuration

> Back to [main README](../README.md)

Load default settings from a YAML or JSON config file using the `-f` flag.
All fields are optional — omitted fields fall back to CLI defaults.  The
format is auto-detected by file extension (`.yaml`/`.yml`/`.json`).

CLI arguments **always** override config file values.

---

## Example `config.yaml`

```yaml
length: 24
count: 1
upper: true
lower: true
digits: true
symbols: true
no_repeats: true
exclude_similar: false
min_chars: 2
allowed_symbols: "!@#$%^&*?`"
blank_space: false
latin_ext: false
save_history: true
clipboard: false
qr: false
# QR code output file (leave blank or comment out to skip).
# qr_file: "password_qr.png"

# Pattern-based generation (overrides character type flags when set).
# Leave blank or comment out to use normal generation.
# pattern: "llbuubddbssbxx"

# Optional metadata defaults
label: "My Default Label"
category: "General"
tags: "default,work"
```

---

## Equivalent `config.json`

```json
{
  "length": 24,
  "count": 1,
  "upper": true,
  "lower": true,
  "digits": true,
  "symbols": true,
  "no_repeats": true,
  "exclude_similar": false,
  "min_chars": 2,
  "allowed_symbols": "!@#$%^&*?`",
  "blank_space": false,
  "latin_ext": false,
  "save_history": true,
  "clipboard": false,
  "qr": false,
  "qr_file": "",
  "pattern": "",
  "label": "My Default Label",
  "category": "General",
  "tags": "default,work"
}
```

---

## Field Reference

|       Field       |  Type  | Description                           |   Default   |
|:-----------------:|:------:|---------------------------------------|:-----------:|
|     `length`      |  int   | Password length (minimum: 8)          |     12      |
|      `count`      |  int   | Number of passwords to generate       |      1      |
|      `upper`      |  bool  | Include uppercase letters             |    false    |
|      `lower`      |  bool  | Include lowercase letters             |    false    |
|     `digits`      |  bool  | Include digits                        |    false    |
|     `symbols`     |  bool  | Include symbols                       |    false    |
|   `no_repeats`    |  bool  | Prevent consecutive duplicates        |    false    |
| `exclude_similar` |  bool  | Exclude similar-looking characters    |    false    |
|    `min_chars`    |  int   | Minimum characters per selected type  |      1      |
| `allowed_symbols` | string | Custom symbol set                     | All symbols |
|   `blank_space`   |  bool  | Include space character               |    false    |
|    `latin_ext`    |  bool  | Include Latin-1 Supplement characters |    false    |
|    `pattern`      | string | Pattern string (blank = normal mode)  |    None     |
|  `save_history`   |  bool  | Save password to encrypted history    |    true     |
|   `clipboard`     |  bool  | Copy password to clipboard            |    false    |
|       `qr`        |  bool  | Display QR code in terminal           |    false    |
|    `qr_file`      | string | Save QR code to PNG file              |    None     |
|      `label`      | string | Default label for passwords           |  "Unnamed"  |
|    `category`     | string | Default category for passwords        |  "General"  |
|      `tags`       | string | Comma-separated default tags          |    None     |

---

## Usage

```bash
# Use YAML config
pwgen -f config.yaml

# Use JSON config with CLI override
pwgen -f config.json -L 32

# Config + additional flags (CLI always wins)
pwgen -f config.yaml --label "Override" -c 5
```

> **Note:** Clipboard auto-clear timeout is controlled by the code-level
> constant `CLIPBOARD_CLEAR_SECONDS` (default `60`) in `constants.py`,
> not by the config file.  Master password setup is CLI-only
> (`--set-master-password`).
