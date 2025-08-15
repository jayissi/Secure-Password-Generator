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
  - Symbols (`!@#$%^&*`, etc.)
- **Complexity Guaranteed**: Enforce a minimum number of characters from each selected character set to meet strict password policies.
- **Secure Local Storage**: Optionally saves the generated password to a local file (`.passwordlist.txt`) with restricted permissions (`0o600`) to prevent unauthorized access.
- **Zero Dependencies**: Pure Python script. No external libraries are needed—just a standard Python 3 installation.
- **User-Friendly CLI**: A clean and straightforward command-line interface built with `argparse`.

---

## 🚀 Getting Started

### 🔍 Prerequisites

You just need **Python 3.7+** installed on your system.

### 🛠️ Installation

1.  Clone this repository to your local machine:
    ```bash
    git clone https://github.com/jayissi/Secure-Password-Generator.git
    ```
2.  Navigate into the project directory:
    ```bash
    cd Secure-Password-Generator
    ```

That's it! You're ready to generate passwords.

---

## 💻 Usage

Run the script from your terminal using `python password_generator.py` with your desired options.

If you run the script with no arguments or with the `-h` flag, it will display the help menu.

```bash
python password_generator.py --help
```

### ⚙️ Command-Line Arguments

| Argument       | Short Form | Description                                 | Default |
| :------------: | :--------: | :------------------------------------------ | :-----: |
| `--length`     |    `-L`    | Sets the length of the password             | `12`    |
| `--upper`      |    `-u`    | Includes uppercase letters (A-Z)            | `False` |
| `--lower`      |    `-l`    | Includes lowercase letters (a-z)            | `False` |
| `--digits`     |    `-d`    | Includes digits (0-9)                       | `False` |
| `--symbols`    |    `-s`    | Includes symbols (e.g., !@#$%^&*)           | `False` |
| `--min`        |  `--min`   | Minimum characters from each selected type  | `1`     |
| `--no-save`    |    `-n`    | Prevents password from being saved to file  | `False` |
| `--help`       |    `-h`    | Shows the help message and exits            |  N/A    |

##  📝 Examples

**1. Generate a default password**
This will create a 12-character password using all character types and save it to `.passwordlist.txt`.

```bash
python password_generator.py -u -l -d -s
```
**Output:**
```
Generated Password: p@55W0rD_Ex&mpl3
Password securely saved to .passwordlist.txt
```

**2. Generate a long, complex password without saving it**
This creates a 24-character password for one-time use.

```bash
python password_generator.py -L 24 --upper --lower --digits --symbols --no-save
```
**Output:**
```
Generated Password: V3ry-L0ng&S3cur3!P@ssw0rd#
```

**3. Generate a password that meets strict requirements**
Create a 16-character password with at least 2 of each selected character type.

```bash
python password_generator.py -L 16 --upper --lower --digits --min 2 --no-save
```

**4. Generate a simple 8-digit PIN**
Create a password using only digits.

```bash
python password_generator.py -L 8 --digits --no-save
```

---

## 🛡️ Security Note

This tool is designed with security as a top priority.
-   Uses `secrets` module instead of `random` for cryptographically secure random number generation
-   Automatically enforces minimum password length of 8 characters
-   By default when passwords are saved, the file permissions for `.passwordlist.txt` are set to `0o600`. This ensures that only the file's owner has read and write permissions, protecting it from other users on the system.
-   Passwords are securely shuffled before being returned

**Disclaimer:** You are responsible for the secure management of the `.passwordlist.txt` file. Ensure it is stored and secured properly.

---

## 🤝 Contributing

Contributions are welcome! Please open an issue or pull request for any improvements.

---

## 📜 License

This project is licensed under the MIT License. See the [LICENSE](https://github.com/jayissi/Secure-Password-Generator/blob/main/LICENSE) file for more details.

