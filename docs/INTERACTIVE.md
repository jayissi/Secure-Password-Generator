# 🖥️ Interactive Mode

> Back to [main README](../README.md)

Interactive mode provides a guided REPL (Read-Eval-Print Loop) for
password generation and vault management.  It is designed for users who
prefer step-by-step prompts over memorising CLI flags.

---

## Starting Interactive Mode

```bash
pwgen -i
```

or equivalently:

```bash
pwgen --interactive
```

You will see:

```text
Welcome to Secure Password Generator — interactive mode.
Type 'help' for available commands.

pwgen>
```

---

## Commands

### Guided Commands

| Command          | Description                                  |
|:-----------------|:---------------------------------------------|
| `quick [LENGTH]` | Generate a password with all character types |
| `new`            | Guided wizard for custom generation          |
| `browse`         | Paginated vault browser                      |
| `health`         | Vault health report                          |

### CLI-Style Commands

| Command                        | Description                                     |
|:-------------------------------|:------------------------------------------------|
| `generate [flags]`             | Generate passwords with CLI flags               |
| `history [--search S]`         | Show / search / filter vault history            |
| `delete <INDEX>`               | Delete a vault entry by index                   |
| `label <INDEX> [--label L]`    | Update metadata on a vault entry by index       |
| `cleanup`                      | Securely delete all vault files                 |

### Session

| Command          | Description                                  |
|:-----------------|:---------------------------------------------|
| `help`           | List available commands                      |
| `clear`          | Clear the terminal screen                    |
| `quit` / `exit`  | Exit interactive mode                        |

---

## `quick` — Fast Generation

Generate a password using all character types (uppercase, lowercase,
digits, symbols) with no consecutive duplicates.  Defaults to 24
characters.

```text
pwgen> quick
  Xk9!mRq2Lp#wYn7@Fj4&bC5  [9/10]

[c]opy  [Q]R  [r]egenerate  [s]ave  [q]uit: s
Label [Unnamed]: My API Key
Category [General]: Development
Tags (comma-separated) []: api,work
[+] Password saved to vault
```

Specify a custom length:

```text
pwgen> quick 32
  Gy7@jPm1Ws#rKf9&Lx2!Bv3$hTz8Qc!e  [10/10]

[c]opy  [Q]R  [r]egenerate  [s]ave  [q]uit: c
[+] Copied to clipboard
[c]opy  [Q]R  [r]egenerate  [s]ave  [q]uit: q
```

### Action Prompt

After generating, you can:

| Key | Action                                    |
|:---:|:------------------------------------------|
| `c` | Copy password to clipboard                |
| `Q` | Display password as QR code in terminal   |
| `r` | Regenerate a new password (same settings) |
| `s` | Save to vault with label/category/tags    |
| `q` | Return to the `pwgen>` prompt             |

---

## `new` — Custom Password Wizard

Walk through each option with defaults shown in brackets:

```text
pwgen> new
Length [24]: 16
Include uppercase? [Y/n]: Y
Include lowercase? [Y/n]: Y
Include digits? [Y/n]: Y
Include symbols? [Y/n]: n

  Xk9mRq2Lp3wYn7F  [7/10]

[c]opy  [Q]R  [r]egenerate  [s]ave  [q]uit:
```

Press Enter to accept defaults.  Type `n` to skip a character type.

---

## `browse` — Vault Browser

View saved passwords in a paginated list (5 per page):

```text
pwgen> browse

--- Page 1/3 (12 entries) ---

  1. Gmail Account  [8/10]
  2. Bank Login  [9/10]
  3. API Key  [7/10]
  4. SSH Key  [10/10]
  5. VPN Access  [8/10]

[n]ext  [p]revious  [v]iew #  [s]earch  [q]uit: v 2

  Label:    Bank Login
  Password: 16DB<dNrUb9{xQ3!
  Strength: █████████░ 9/10
  Category: Banking
  Tags:     finance, important
  Created:  Mon, Nov 15, 2025 08:55:12:000000 AM

[c]opy  [Q]R  [b]ack:
```

### Browse Actions

| Key  | Action                           |
|:----:|:---------------------------------|
|  `n` | Next page                        |
|  `p` | Previous page                    |
| `v #`| View full details for entry `#`  |
|  `s` | Search entries by keyword        |
|  `q` | Return to the `pwgen>` prompt    |

### Entry Detail Actions

| Key | Action                          |
|:---:|:--------------------------------|
| `c` | Copy password                   |
| `Q` | Display password as QR code     |
| `b` | Back to browse list             |

---

## `health` — Vault Health Report

Get an overview of your vault's security posture:

```text
pwgen> health

  Total passwords: 12

  Score distribution:
    ██████████ 10/10: 3
    █████████░  9/10: 5
    ████████░░  8/10: 3
    ██████░░░░  6/10: 1

  Oldest entry: Mon, Nov 15, 2025 08:55:12:000000 AM

  ✓ All passwords score 5/10 or above.
```

If weak passwords are found:

```text
  ⚠ 2 password(s) scored below 5/10 — consider regenerating.
```

Duplicate labels are also flagged:

```text
  Duplicate labels: Gmail Account, Work VPN
```

---

## CLI-Style Command Reference

These commands accept the same flags as the non-interactive CLI, giving
power users the familiar flag syntax directly inside the REPL.

### `generate` — Generate with CLI Flags

Generate a single password and choose what to do with it:

```text
pwgen> generate -F -L 20
Generated Password 1: Xk9!mRq2Lp#wYn7@Fj4b  [9/10]

Strength Summary: 1 password generated
  █████████░  9/10: 1 password

[c]opy  [Q]R  [r]egenerate  [s]ave  [q]uit: s
Label [Unnamed]: My API Key
Category [General]: Development
Tags (comma-separated) []: api,work
[+] 1 password saved to vault
```

Generate multiple passwords as a batch — all are displayed first,
then you decide whether to save them all at once:

```text
pwgen> generate -F -L 16 -c 3
Generated Password 1: Xk9!mRq2Lp#wYn7@  [9/10]
Generated Password 2: bT5$jHn8Wv@zQp3!  [9/10]
Generated Password 3: cR7&kLm4Nx#yAs2%  [9/10]

Strength Summary: 3 passwords generated
  █████████░  9/10: 3 passwords

[c]opy  [Q]R  [r]egenerate  [s]ave  [q]uit: s
Label [Unnamed]: Gmail
Category [General]: Email
Tags (comma-separated) []: work
[+] 3 passwords saved to vault
```

#### `generate` Flags

| Flag | Long                | Description                      |
|:-----|:--------------------|:---------------------------------|
| `-F` | `--full`            | All types + no-repeats           |
| `-L` | `--length N`        | Password length (default: 12)    |
| `-c` | `--count N`         | Number of passwords (default: 1) |
| `-u` | `--upper`           | Include uppercase                |
| `-l` | `--lower`           | Include lowercase                |
| `-d` | `--digits`          | Include digits                   |
| `-s` | `--symbols`         | Include symbols                  |
| `-a` | `--allowed-symbols` | Custom symbol set (implies `-s`) |
| `-x` | `--latin-ext`       | Latin-1 extended characters      |
| `-b` | `--blank`           | Include space character          |
| `-r` | `--no-repeats`      | No consecutive duplicates        |
| `-e` | `--exclude-similar` | Exclude i/l/1/L/o/0/O            |
| `-m` | `--min N`           | Min chars per selected type      |
| `-p` | `--pattern P`       | Pattern (l/u/d/s/b/*)            |
| `-n` | `--no-save`         | Just print, skip prompt          |

### `history` — Search & Filter History

```text
pwgen> history
pwgen> history --search Gmail
pwgen> history --filter-strength 8
pwgen> history --filter-category Email --limit 5
pwgen> history --since 2025-01-01
```

### `delete` — Remove Entry by Index

```text
pwgen> history
  (view entry numbers)

pwgen> delete 3
[+] Entry 3 securely deleted
```

### `label` — Update Entry Metadata

Update the label, category, or tags on any vault entry by its index
(newest first):

```text
pwgen> label 1 --label "Gmail" --category "Email" --tags "work,important"
[+] Entry 1 updated
```

Only the flags you pass are changed; omitted fields keep their current
values:

```text
pwgen> label 2 --category "Finance"
[+] Entry 2 updated
```

#### `label` Flags

| Positional / Flag | Description                  |
|:------------------|:-----------------------------|
| `<INDEX>`         | Entry index (newest first)   |
| `--label L`       | New label                    |
| `--category C`    | New category                 |
| `--tags T`        | Comma-separated tags         |

### `generate` with Metadata

Pass `--label`, `--category`, and `--tags` to pre-fill the save
prompt.  The flags override anything typed at the interactive prompt:

```text
pwgen> generate -F -L 20 --label "Gmail" --category "Email" --tags "work"
Generated Password 1: Xk9!mRq2Lp#wYn7@Fj4b  [9/10]

Strength Summary: 1 password generated
  █████████░  9/10: 1 password

[c]opy  [Q]R  [r]egenerate  [s]ave  [q]uit: s
Label [Unnamed]:
Category [General]:
Tags (comma-separated) []:
[+] 1 password saved to vault
```

### `cleanup` — Secure Delete All Vault Files

```text
pwgen> cleanup
Are you sure? This will securely delete all vault files. [y/N]: y
[+] Securely removed: ...
[+] Session key cleared
```

---

## Session Key Caching

The master password is prompted **once** on the first vault operation
(browse, health, or saving a password).  The derived encryption key is
cached for the duration of the interactive session.

When you `quit` or `exit`, all cached keys are securely cleared.

---

## Exiting

Any of these will exit the REPL:

```text
pwgen> quit
pwgen> exit
```

Or press **Ctrl+D** (EOF).

---

## readline Support

Interactive mode supports readline for command history and line editing
(arrow keys, Ctrl+A/E, etc.) when available on your system.
