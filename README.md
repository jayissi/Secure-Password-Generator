# 🔐 Secure Password Generator

A robust, powerful, and secure command-line tool for generating cryptographically strong passwords. This script uses Python's `secrets` module to create strong random passwords with customizable character sets and minimum character requirements.

![Python Version](https://img.shields.io/badge/python-3.7+-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![Security](https://img.shields.io/badge/security-cryptographically_secure-red.svg)

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

### Prerequisites

You just need **Python 3.7+** installed on your system.

### Installation

1.  Clone this repository to your local machine:
    ```bash
    git clone [https://github.com/your-username/your-repository-name.git](https://github.com/your-username/your-repository-name.git)
    ```
2.  Navigate into the project directory:
    ```bash
    cd your-repository-name
    ```

That's it! You're ready to generate passwords.

---

## 💻 Usage

Run the script from your terminal using `python3 password_generator.py` with your desired options.

If you run the script with no arguments or with the `-h` flag, it will display the help menu.

```bash
python3 password_generator.py --help
```

### Command-Line Arguments

| Argument      | Short Form | Description                                  | Default |
| :------------ | :--------: | :------------------------------------------- | :------ |
| `--length`    |     `-l`     | Sets the length of the password.             | `12`    |
| `--upper`     |            | Includes uppercase letters (A-Z).            | `False` |
| `--lower`     |            | Includes lowercase letters (a-z).            | `False` |
| `--digits`    |            | Includes digits (0-9).                       | `False` |
| `--symbols`   |            | Includes symbols (e.g., !@#$%^&*).           | `False` |
| `--min-chars` |            | Minimum characters from each selected type.  | `1`     |
| `--no-save`   |            | Prevents the password from being saved to the file. | `False` |
| `--help`      |     `-h`     | Shows the help message and exits.            | N/A     |

##  📝 Examples

**1. Generate a default password**
This will create a 12-character password using all character types and save it to `.passwordlist.txt`.

```bash
python3 password_generator.py --upper --lower --digits --symbols
```
**Output:**
```
Generated Password: "p@55W0rD_Ex&mpl3"
Password securely saved to .passwordlist.txt
```

**2. Generate a long, complex password without saving it**
This creates a 24-character password for one-time use.

```bash
python3 password_generator.py -l 24 --upper --lower --digits --symbols --no-save
```
**Output:**
```
Generated Password: "V3ry-L0ng&S3cur3!P@ssw0rd#"
```

**3. Generate a password that meets strict requirements**
Create a 16-character password with at least 2 of each selected character type.

```bash
python3 password_generator.py -l 16 --upper --lower --digits --min-chars 2 --no-save
```

**4. Generate a simple 8-digit PIN**
Create a password using only digits.

```bash
python3 password_generator.py -l 8 --digits --no-save
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

This project is licensed under the MIT License. See the `LICENSE` file for more details.

