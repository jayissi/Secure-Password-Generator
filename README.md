# 🔐 Secure Password Generator

![Python Version](https://img.shields.io/badge/python-3.7+-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![Security](https://img.shields.io/badge/security-cryptographically_secure-red.svg)

A robust, powerful, and secure command-line tool for generating cryptographically strong passwords. This script uses Python's `secrets` module to create strong random passwords with customizable character sets and minimum character requirements.

<p align="center">
<img alt="Python" src="https://www.python.org/static/community_logos/python-logo-master-v3-TM.png">
</p>

---

## ✨ Features

- **Cryptographically Secure**: Utilizes Python's `secrets` module, which is designed to generate unpredictable random numbers for cryptographic purposes.
- **Customizable password length** (minimum 8 characters enforced)
- **Flexible character sets**:
  - Uppercase letters (`A-Z`)
  - Lowercase letters (`a-z`)
  - Digits (`0-9`)
  - Symbols (customizable or default punctuation)
- **Advanced options**:
  - Minimum character requirements per character type
  - Exclude similar-looking characters (`i`, `l`, `1`, `L`, `o`, `0`, `O`)
  - Prevent consecutive duplicate characters
  - Custom allowed symbols for specific requirements
- **Bulk generation**: Generate multiple passwords at once
- **Password history**: View previously generated passwords
- **Complexity Guaranteed**: Enforce a minimum number of characters from each selected character set to meet strict password policies.
- **Secure Local Storage**: Optionally saves the generated password to a local file (`${HOME}/.password_list.txt`) with restricted permissions (`0o600`) to prevent unauthorized access.
- **User-Friendly CLI**: A clean and straightforward command-line interface built with `argparse`.
- **Zero Dependencies**: Pure Python script. No external libraries are needed—just a standard Python 3 installation.

---

## 🚀 Getting Started

### 🔍 Prerequisites

You just need **Python 3.7+** installed on your system.

### 🛠️ Installation

1. Clone this repository to your local machine:

    ```bash
    git clone https://github.com/jayissi/Secure-Password-Generator.git
    ```

2. Make the script executable:

    ```bash
    chmod +x Secure-Password-Generator/password_generator.py
    ```

3. Move it to your local bin folder (on Linux/macOS):

    ```bash
    sudo mv Secure-Password-Generator/password_generator.py /usr/local/bin/password_generator
    ```

That's it! You're ready to generate passwords.

---

## 💻 Usage

Run the script from your terminal using `password_generator` with your desired options.

If you run the script with no arguments or with the `-h` flag, it will display the help menu.

```bash
password_generator -h
```

### ⚙️ Command-Line Arguments

| Argument               | Short | Description                                  | Default |
|:----------------------:|:-----:|----------------------------------------------|:-------:|
| `--length`             | `-L`  | Password length (min: 8)                     | 12      |
| `--upper`              | `-u`  | Include uppercase letters                    | False   |
| `--lower`              | `-l`  | Include lowercase letters                    | False   |
| `--digits`             | `-d`  | Include digits                               | False   |
| `--symbols`            | `-s`  | Include symbols                              | False   |
| `--allowed-symbols`    | `-a`  | Custom allowed symbols (implies `--symbols`) | None    |
| `--min`                | `-m`  | Min chars per selected type                  | 1       |
| `--count`              | `-c`  | Number of passwords to generate              | 1       |
| `--exclude-similar`    | `-e`  | Exclude similar-looking chars                | False   |
| `--no-repeats`         | `-r`  | No consecutive duplicate chars               | False   |
| `--no-save`            | `-n`  | Don't save to password file                  | False   |
| `--show-history`       | `-H`  | Show password history                        | False   |
| `--help`               | `-h`  | Show help message                            | N/A     |

## 📝 Examples

**1. Generate a default password**
Create a 16-character password using all character types and save it to `${HOME}/.password_list.txt`.

```bash
password_generator -L 16 -u -l -d -s
```

**Output:**

```bash
Generated Password: p@55W0rD_Ex&mpl3
Password securely saved to ${HOME}/.password_list.txt
```

**2. Generate a long, complex password without saving it**
This creates a 26-character password with no repetitive characters.

```bash
password_generator -L 26 --upper --lower --digits --symbols --no-repeats --no-save
```

**Output:**

```bash
Generated Password: V3ry-L0ng&S3cur3!P@ssw0rd#
```

**3. Generate a password that meets strict requirements**
Create a 16-character password with at least 2 of each selected character type.

```bash
password_generator -L 16 --upper --lower --digits --symbols --no-repeats --min 2 --no-save
```

**4. Custom symbol set**
Create a password using only `@#$%` as symbols

```bash
password_generator -n -u -l -a '@#$%'
```

**5. Advanced Requirements**
Create (5x) 20-character password with:

- At least 3 of each character type
- No similar characters
- No consecutive duplicates
- Only use `!@*#^ $&%\"` as valid symbols
- Output to stdout only

```bash
password_generator -c 5 -L 20 -u -l -d -m 3 -e -r -a '!@*#^ $&%\"' -n
```

---

## 🛡️ Security Note

This tool is designed with security as a top priority.

- Uses `secrets` module instead of `random` for cryptographically secure random number generation
- Automatically enforces minimum password length of 8 characters
- By default when passwords are saved, the file permissions for `${HOME}/.password_list.txt` are set to `0o600`. This ensures that only the file's owner has read and write permissions, protecting it from other users on the system.
- Passwords are securely shuffled before being returned

**Disclaimer:** You are responsible for the secure management of the `${HOME}/.password_list.txt` file. Ensure it is stored and secured properly.

---

## 🤝 Contributing

Contributions are welcome! Please open an issue or pull request for any improvements.

---

## 📜 License

This project is licensed under the MIT License. See the [LICENSE](https://github.com/jayissi/Secure-Password-Generator/blob/main/LICENSE) file for more details.
