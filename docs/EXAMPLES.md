# 📝 Examples

> Back to [main README](../README.md)

Comprehensive usage examples for the Secure Password Generator, organised
by use case.  Each section shows the command, what it does, and the
expected output format.

---

## Basic Generation

### Generate a single strong password

```bash
pwgen -F -L 16
```

```text
Generated Password 1: p@55W0rD Ex&mpl3  [8/10]

Strength Summary: 1 password generated
  ████████░░ 8/10: 1 password
[+] Passwords securely saved to /home/user/.secure_passwords/vault.enc
```

### Generate multiple passwords

```bash
pwgen -F -L 20 -c 3 -n
```

```text
Generated Password 1: Xk9!mRq2Lp#wYn7@Fj4&  [9/10]
Generated Password 2: Bv3$hTz8Qc!eAw5%Nd6*  [9/10]
Generated Password 3: Gy7@jPm1Ws#rKf9&Lx2!  [9/10]

Strength Summary: 3 passwords generated
  █████████░ 9/10: 3 passwords
```

### Generate with metadata (label, category, tags)

```bash
pwgen -F -L 16 --label "Gmail Account" --category "Email" --tags "work,important"
```

```text
Generated Password 1: C1l|T3qZ7KfTqp8  [8/10]

Strength Summary: 1 password generated
  ████████░░ 8/10: 1 password
[+] Passwords securely saved to /home/user/.secure_passwords/vault.enc
```

---

## Character Type Control

### Uppercase and lowercase only

```bash
pwgen -u -l -L 16 -n
```

### Digits only

```bash
pwgen -d -L 12 -n
```

### Custom symbol set

Use `-a` to restrict which symbols are included (implies `--symbols`):

```bash
pwgen -u -l -d -a '!@#$%' -L 20 -n
```

### Latin-1 Supplement characters

Add accented letters and extended symbols with `--latin-ext`:

```bash
pwgen -F -x -L 20 -n
```

```text
Generated Password 1: Ñk3!ëRq2Lp#wÿn7@Fj  [10/10]

Strength Summary: 1 password generated
  ██████████ 10/10: 1 password
```

---

## Advanced Constraints

### No consecutive duplicate characters

```bash
pwgen -F -L 24 -r -n
```

### Exclude similar-looking characters

Remove `i`, `l`, `1`, `L`, `o`, `0`, `O` from the pool:

```bash
pwgen -F -L 16 -e -n
```

### Minimum characters per type

Ensure at least 3 characters from each selected type:

```bash
pwgen -u -l -d -s -L 20 -m 3 -n
```

### Include blank (space) character

Blanks are never placed as the first or last character:

```bash
pwgen -F -b -L 24 -n
```

### Combined advanced options

```bash
pwgen -c 5 -L 20 -u -l -d -m 3 -e -r -a '!@*#^$&%' -n
```

---

## Pattern-Based Generation

Define exact character positions using pattern codes:

| Code | Character type |
|:----:|----------------|
|  `l` | lowercase      |
|  `u` | uppercase      |
|  `d` | digit          |
|  `s` | symbol         |
|  `b` | blank (space)  |
|  `*` | any            |

### Simple pattern

```bash
pwgen --pattern 'lluuddss' --label "Pattern Test" -n
```

### Mixed pattern with wildcards

```bash
pwgen --pattern '****lluu' -n
```

### PIN-style code

```bash
pwgen --pattern 'dddddddd' -n
```

---

## Config File Usage

Load defaults from a YAML or JSON file.  CLI arguments always override
config values.

### YAML config

```bash
pwgen -f config.yaml
```

### JSON config with CLI override

```bash
pwgen -f config.json -L 32
```

See [CONFIGURATION.md](CONFIGURATION.md) for the full field reference.

---

## History Management

### View all saved passwords

```bash
pwgen -H
```

```text
┌─────┬───────────────┬──────────────────────┬────────────┬────────────┬──────────────────┐
│   # │ Label         │ Password             │ Strength   │ Category   │ Created          │
├─────┼───────────────┼──────────────────────┼────────────┼────────────┼──────────────────┤
│   1 │ Gmail Account │ C1l|T3qZ7KfTqp8      │ 8/10       │ Email      │ 2025-11-15 08:56 │
│   2 │ Bank Account  │ 16DB<dNrUb9{         │ 6/10       │ Banking    │ 2025-11-15 08:55 │
└─────┴───────────────┴──────────────────────┴────────────┴────────────┴──────────────────┘
```

### Search by label, category, or tags

```bash
pwgen -H --search "Gmail"
```

### Filter by category and minimum strength

```bash
pwgen -H --filter-category "Email" --filter-strength 7 --limit 5
```

### Filter by date

```bash
pwgen -H --since 2025-01-01
```

### Delete an entry (authenticated)

```bash
pwgen --delete-entry 1
```

---

## Master Password Workflows

### First-time setup (interactive prompts)

```bash
pwgen --set-master-password
```

### Unlock vault (automatic when `master_salt.bin` exists)

```bash
pwgen -U -H
```

### Environment variable (less secure — visible in `/proc`)

```bash
export SPG_MASTER_PASSWORD='YourSecret'
pwgen -H
```

### Password file (recommended for CI/automation)

```bash
echo 'YourSecret' > /tmp/mp.txt && chmod 600 /tmp/mp.txt
pwgen --master-password-file /tmp/mp.txt -H
```

### Direct CLI flag (least secure — visible in process lists)

```bash
pwgen --master-password 'YourSecret' -H
```

> **Master password requirements:** minimum 12 characters, at least
> 3 of 4 character types (uppercase, lowercase, digit, special).

---

## Batch Generation with Strength Summary

```bash
pwgen -F -L 24 -c 10 -n
```

The strength summary at the end groups passwords by score:

```text
Strength Summary: 10 passwords generated
  ██████████ 10/10: 4 passwords
  █████████░  9/10: 6 passwords
```

---

## Custom Passphrase

Store a user-provided passphrase with metadata:

```bash
pwgen -P "MySecurePass123!" --label "Custom Pass" --category "Personal" --tags "manual"
```

---

## Secure Cleanup

Securely delete all password and key files (including master salt):

```bash
pwgen -C
```

---

## Interactive Mode

Start the guided interactive REPL:

```bash
pwgen -i
```

### Generate with metadata in interactive mode

```text
pwgen> generate -F -L 16 --label "Gmail" --category "Email" --tags "work"
Generated Password 1: Xk9!mRq2Lp#wYn7@  [9/10]

Strength Summary: 1 password generated
  █████████░ 9/10: 1 password
[+] Passwords securely saved to ...
```

### Update metadata on an existing entry

```text
pwgen> label 1 --label "Gmail Work" --tags "work,important"
[+] Entry 1 updated
```

See [INTERACTIVE.md](INTERACTIVE.md) for the full command reference.
