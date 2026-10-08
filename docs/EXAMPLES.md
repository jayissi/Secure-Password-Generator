# 📝 Examples

> Back to [main README](../README.md)

A hands-on guide to the Secure Password Generator.  **Part 1** walks
through every flag one at a time so you can see exactly what each one
does.  **Part 2** is a recipe book of copy-paste commands for real-world
tasks.

---

## Part 1: Learn the Flags

Each section introduces one flag (or flag group), shows the command, and
explains the output.  Follow along in order to watch the strength score
climb as you add more character types.

### 1. Your First Password (`-l`, `-L`, `-n`)

Start with the simplest possible password — lowercase letters only.
Three flags are all you need:

```text
    pwgen -l -L 12 -n
    #     ^^ ^^^^ ^^
    #     |  |    └─ don't save to vault
    #     |  └─ length: 12 characters
    #     └─ include lowercase letters
```

```text
Generated Password 1: qxmtbfjwrsgk  [3/10]

Strength Summary: 1 password generated
  ███░░░░░░░ 3/10: 1 password
```

A 3/10 is weak — the pool is only 26 characters.  Keep reading to see
the score improve.

---

### 2. Adding Uppercase (`-u`)

Layer in uppercase letters to double the character pool:

```text
    pwgen -u -l -L 12 -n
    #     ^^ ^^  ^^^^ ^^
    #     |  |   |    └─ don't save to vault
    #     |  |   └─ length: 12 characters
    #     |  └─ include lowercase
    #     └─ include uppercase
```

```text
Generated Password 1: kRqYmLwBxTfJ  [5/10]

Strength Summary: 1 password generated
  █████░░░░░ 5/10: 1 password
```

Two character types push the score from 3 to **5/10**.

---

### 3. Adding Digits (`-d`)

Add digits to reach three character types:

```text
    pwgen -u -l -d -L 12 -n
    #     ^^ ^^ ^^ ^^^^ ^^
    #     |  |  |  |    └─ don't save to vault
    #     |  |  |  └─ length: 12 characters
    #     |  |  └─ include digits
    #     |  └─ include lowercase
    #     └─ include uppercase
```

```text
Generated Password 1: Xk9mRq2LpYn7  [6/10]

Strength Summary: 1 password generated
  ██████░░░░ 6/10: 1 password
```

Three types earns a diversity bonus — up to **6/10**.

---

### 4. Adding Symbols (`-s`)

Complete the basic four character types with symbols:

```text
    pwgen -u -l -d -s -L 12 -n
    #     ^^ ^^ ^^ ^^ ^^^^ ^^
    #     |  |  |  |  |    └─ don't save to vault
    #     |  |  |  |  └─ length: 12 characters
    #     |  |  |  └─ include symbols
    #     |  |  └─ include digits
    #     |  └─ include lowercase
    #     └─ include uppercase
```

```text
Generated Password 1: Xk9!mRq2Lp#w  [7/10]

Strength Summary: 1 password generated
  ███████░░░ 7/10: 1 password
```

Four types = **7/10** at length 12.  To go higher, increase the length
(see section 6).

---

### 5. The Full Shortcut (`-F`)

Typing `-u -l -d -s -r` every time is tedious.  The `-F` flag enables
**all four character types** plus **no consecutive repeats** in a single
switch:

```bash
# These two commands are equivalent:
pwgen -u -l -d -s -r -L 12 -n
pwgen -F -L 12 -n              # same thing, shorter
```

> **Note:** `-F` does *not* enable `-b` (blank), `-x` (Latin-1), or
> `-e` (exclude similar).  Those remain opt-in.

---

### 6. Controlling Length (`-L`)

Length is the single biggest lever for entropy.  The minimum is 8; the
default is 12.

```bash
pwgen -F -L 8 -n     # 8 chars  → typically 6/10
pwgen -F -L 16 -n    # 16 chars → typically 9/10
pwgen -F -L 24 -n    # 24 chars → typically 10/10
pwgen -F -L 32 -n    # 32 chars → 10/10
```

```text
Generated Password 1: Xk9!mRq2Lp#wYn7@  [9/10]

Strength Summary: 1 password generated
  █████████░ 9/10: 1 password
```

If you ask for fewer than 8, the tool automatically rounds up:

```text
⚠ Password length increased to minimum of 8 characters
```

---

### 7. Multiple Passwords (`-c`)

Generate a batch and get a strength summary at the end:

```bash
pwgen -F -L 16 -c 5 -n   # five 16-character passwords
```

```text
Generated Password 1: Xk9!mRq2Lp#wYn7@  [9/10]
Generated Password 2: Bv3$hTz8Qc!eAw5%  [9/10]
Generated Password 3: Gy7@jPm1Ws#rKf9&  [9/10]
Generated Password 4: Nd6*Lx2!Fy4^Ht8(  [10/10]
Generated Password 5: Qr5)Mz3#Jw7&Ep1!  [10/10]

Strength Summary: 5 passwords generated
  ██████████ 10/10: 2 passwords
  █████████░  9/10: 3 passwords
```

---

### 8. Custom Symbols (`-a`)

Restrict the symbol set to only the characters you specify.  Passing
`-a` automatically implies `-s` (symbols enabled):

```bash
pwgen -u -l -d -a '!@#$' -L 16 -n   # only these 4 symbols allowed
```

Use this when a service forbids certain special characters.

---

### 9. Latin-1 Extended Characters (`-x`)

Add accented letters and extended symbols (93 extra characters from
U+00A1 to U+00FF) for a much larger pool:

```bash
pwgen -F -x -L 16 -n   # -x adds Latin-1 Supplement
```

```text
Generated Password 1: Ñk3!ëRq2Lp#wÿn7@  [10/10]

Strength Summary: 1 password generated
  ██████████ 10/10: 1 password
```

Latin-1 introduces a **fifth character type**, which earns an extra
diversity bonus and can push shorter passwords to 10/10.

---

### 10. Blank Characters (`-b`)

Include spaces in the character pool.  Blanks are **never** placed as
the first or last character:

```bash
pwgen -F -b -L 24 -n   # spaces may appear in the interior
```

```text
Generated Password 1: Xk9! mRq2 Lp#w Yn7@ Fj4&  [10/10]
```

Blank adds a **fifth type** (or sixth, with `-x`), boosting the
diversity bonus further.

---

### 11. Exclude Similar Characters (`-e`)

Remove characters that look alike in many fonts — `i`, `l`, `1`, `L`,
`o`, `0`, `O`:

```bash
pwgen -F -e -L 16 -n   # no ambiguous characters
```

Useful for passwords that will be read aloud or printed on paper.

---

### 12. No Consecutive Repeats (`-r`)

Prevent the same character from appearing twice in a row (`aa`, `11`,
etc.):

```bash
pwgen -u -l -d -s -r -L 16 -n   # no back-to-back duplicates
```

> `-F` already includes `-r`, so this flag is mainly useful when you
> build your own character set instead of using `-F`.

---

### 13. Minimum Per Type (`-m`)

Guarantee at least N characters from **each** selected type.  This is
helpful when a service requires "at least 2 digits and 2 symbols":

```bash
pwgen -F -L 16 -m 3 -n   # at least 3 of each type
```

The tool reserves positions for the minimums first, then fills the
remaining slots randomly.

---

### 14. Pattern-Based Generation (`-p`)

Define the exact character type for every position using a pattern
string:

| Code | Character Type            |
|:----:|---------------------------|
|  `l` | Lowercase letter          |
|  `u` | Uppercase letter          |
|  `d` | Digit                     |
|  `s` | Symbol                    |
|  `b` | Blank (space)             |
|  `x` | Latin-1 extended          |
|  `*` | Any (letter/digit/symbol; add `-x` for Latin-1) |

```bash
pwgen -p 'lluuddss' -n         # 8-position pattern
pwgen -p '****lluu' -n         # 4 random + 2 lower + 2 upper
pwgen -p 'dddddddd' -n         # 8-digit PIN
pwgen -p 'uuuu-dddd-llll' -n   # literal hyphens kept as-is
```

If the pattern is shorter than 8 characters, it is padded with `*` to
meet the minimum length.

Pattern mode respects `-r` (no consecutive repeats) and `-e` (exclude
similar characters).  The `x` code always produces Latin-1 characters
without needing `-x`.  The `*` wildcard only includes Latin-1 when
`-x` is passed.  Blank (`b`) cannot be the first or last position.

```bash
pwgen -p 'ssssssssssss' -a '%@!' -r -n  # symbols, no repeats
pwgen -p 'llllllllllll' -e -n            # lowercase, no i/l/o
pwgen -p 'lluuddss' -r -e -n            # pattern + both flags
pwgen -p 'lluuddxx' -n                   # x = Latin-1 (no -x needed)
pwgen -p 'lluu****' -x -n               # * includes Latin-1 with -x
```

---

### 15. Saving and Metadata (`--label`, `--category`, `--tags`, `-n`)

By default, every generated password is saved to the encrypted vault.
Add metadata to keep things organised:

```bash
# Save with full metadata
pwgen -F -L 24 --label "GitHub" --category "Development" --tags "work,2fa"
```

```text
Generated Password 1: Xk9!mRq2Lp#wYn7@Fj4&bC5z  [10/10]

Strength Summary: 1 password generated
  ██████████ 10/10: 1 password
[+] Passwords securely saved to /home/user/.secure_passwords/vault.enc
```

Use `-n` (`--no-save-history`) to generate without saving — handy for
one-off tests or throwaway passwords:

```bash
pwgen -F -L 16 -n   # print only, nothing is saved
```

View your saved passwords with `--show-history` and optional filters:

```bash
pwgen --show-history --search "GitHub"
pwgen --show-history --filter-category "Development" --filter-strength 8
pwgen --show-history --since 2025-01-01 --limit 10
```

---

### 16. Config Files (`-f`)

Load default values from a YAML or JSON file so you don't have to retype
the same flags every time.  CLI arguments **always** override the config:

```bash
pwgen -f config.yaml                  # load defaults
pwgen -f config.json -L 32            # config + CLI override
pwgen -f config.yaml --label "Work"   # override just the label
```

See [CONFIGURATION.md](CONFIGURATION.md) for the full field reference and
sample files.

---

## Part 2: Real-World Recipes

Copy-paste commands for common tasks.  Each recipe assumes you've read
Part 1 and know what the flags do.

### Password Generation

**Wi-Fi passphrase (digits only, 8 characters):**

```bash
pwgen -d -L 8 -n
```

**Bank-grade password (all types, no repeats, 24 characters):**

```bash
pwgen -F -L 24 --label "Bank" --category "Finance" --tags "sensitive"
```

**Batch of 5 API keys (uppercase + digits, 32 characters each):**

```bash
pwgen -u -d -L 32 -c 5 -n
```

**Memorable password with accented characters:**

```bash
pwgen -F -x -L 18 --label "Personal Laptop"
```

**PINs for multiple devices:**

```bash
pwgen -p 'dddddddd' -c 4 -n
```

**Password from a custom pattern:**

```bash
pwgen -p 'uuuullllddddssss' --label "Patterned" -n
```

**Batch generate and review strength distribution:**

```bash
pwgen -F -L 24 -c 10 -n
```

### Vault Management

**First-time master password setup:**

```bash
pwgen --set-master-password
```

**Unlock vault with environment variable (CI/automation):**

```bash
export SPG_MASTER_CREDENTIAL='YourMasterSecret'
pwgen --show-history --limit 5
```

> ⚠️ The env-var is visible in `/proc` — prefer `--master-password-file`
> in production.

**Unlock vault with a password file (scripting):**

```bash
echo 'YourMasterSecret' > /tmp/mp.txt && chmod 600 /tmp/mp.txt
pwgen --master-password-file /tmp/mp.txt --show-history
```

**Search vault for a specific service:**

```bash
pwgen --show-history --search "Gmail"
```

**Filter passwords by category and minimum strength:**

```bash
pwgen --show-history --filter-category "Email" --filter-strength 7 --limit 5
```

**Delete an old password entry (authenticated):**

```bash
pwgen --delete-entry 3
```

**Secure cleanup of all vault files:**

```bash
pwgen -C
```

### Configuration & Automation

**Use a config file for team-standard defaults:**

```bash
pwgen -f team-config.yaml -c 3
```

**Store a user-provided passphrase with metadata:**

```bash
pwgen -P "MyCustomPhrase!" --label "Shared Secret" --category "Team" --tags "manual"
```

**Generate a password and display as QR code:**

```bash
pwgen -F -L 20 -n -q
```

**Save a QR code to a PNG file:**

```bash
pwgen -F -L 20 -n --qr-file password_qr.png
```

**View history with inline QR codes:**

```bash
pwgen -H -q
```

**Start the graphical terminal UI:**

```bash
pwgen -t
```

The TUI provides four tabbed screens -- Generate (g), History (h),
Status (s), and Config (c) -- with keyboard navigation and mouse support.

**Start interactive REPL for guided generation:**

```bash
pwgen --interactive
```

See [INTERACTIVE.md](INTERACTIVE.md) for the full command reference.
