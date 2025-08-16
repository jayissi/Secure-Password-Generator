#!/usr/bin/env python3

import secrets
import string
import argparse
from pathlib import Path
import sys
from typing import Optional, List

DEFAULT_PASSWORD_LENGTH = 12
MIN_PASSWORD_LENGTH = 8
MAX_GENERATION_ATTEMPTS = 100
PASSWORD_FILE = Path.home().joinpath( '.password_list.txt' )
SIMILAR_CHARS = "il1Lo0O"  # Characters to exclude when --exclude-similar is used


def generate_password(
    length: int,
    use_upper: bool,
    use_lower: bool,
    use_digits: bool,
    use_symbols: bool,
    min_characters_per_type: Optional[int] = None,
    exclude_similar: bool = False,
    allowed_symbols: Optional[str] = None,
    no_repeats: bool = False,
) -> str:
    """Generate a cryptographically secure random password."""
    # Enforce minimum length
    if length < MIN_PASSWORD_LENGTH:
        print(
            f"Warning: Password length increased to minimum of {MIN_PASSWORD_LENGTH} characters"
        )
        length = MIN_PASSWORD_LENGTH

    # Determine effective symbol set
    effective_symbols = (
        allowed_symbols
        if allowed_symbols
        else (string.punctuation if use_symbols else "")
    )

    def generate_symbol_only_password(length: int, symbols: str) -> str:
        """Generate password using only symbols with no consecutive repeats."""
        unique_symbols = list(set(symbols))  # Get unique symbols
        num_symbols = len(unique_symbols)

        if num_symbols == 1:
            raise ValueError(
                "Cannot generate password with --no-repeats using only 1 symbol. "
                "Add more symbols or enable other character types."
            )

        # Generate password using random walk through symbols
        password = []
        last_char = None
        symbol_counts = {s: 0 for s in unique_symbols}
        target_count = length // num_symbols

        while len(password) < length:
            # Create candidate pool excluding last used character
            candidates = [s for s in unique_symbols if s != last_char]

            # Prioritize symbols that are underused
            underused = [s for s in candidates if symbol_counts[s] < target_count]
            if underused:
                candidates = underused

            # Select randomly from remaining candidates
            char = secrets.choice(candidates)
            password.append(char)
            symbol_counts[char] += 1
            last_char = char

        return "".join(password)

    # In the validate symbol-only scenarios section:
    if effective_symbols and not (use_upper or use_lower or use_digits):
        if no_repeats:
            return generate_symbol_only_password(length, effective_symbols)
        elif len(set(effective_symbols)) < 2 and length > 1:
            raise ValueError(
                "Cannot generate password with only 1 symbol and length > 1. "
                "Add more symbols or enable other character types."
            )

    # Generate character sets
    character_sets = []
    charset_info = []

    if use_upper:
        upper = string.ascii_uppercase
        if exclude_similar:
            upper = "".join(c for c in upper if c not in SIMILAR_CHARS)
        character_sets.append(upper)
        charset_info.append(("uppercase", upper))

    if use_lower:
        lower = string.ascii_lowercase
        if exclude_similar:
            lower = "".join(c for c in lower if c not in SIMILAR_CHARS)
        character_sets.append(lower)
        charset_info.append(("lowercase", lower))

    if use_digits:
        digits = string.digits
        if exclude_similar:
            digits = "".join(c for c in digits if c not in SIMILAR_CHARS)
        character_sets.append(digits)
        charset_info.append(("digits", digits))

    if effective_symbols:
        character_sets.append(effective_symbols)
        charset_info.append(("symbols", effective_symbols))

    # Validate character sets
    for name, chars in charset_info:
        if not chars:
            raise ValueError(f"No {name} characters available after filtering")

    if not character_sets:
        raise ValueError("At least one character type must be selected.")

    # Generation attempts
    for attempt in range(MAX_GENERATION_ATTEMPTS):
        try:
            all_chars = "".join(character_sets)

            if no_repeats:
                password = []
                last_char = None
                while len(password) < length:
                    char = secrets.choice(all_chars)
                    if char != last_char:
                        password.append(char)
                        last_char = char
            else:
                password = [secrets.choice(all_chars) for _ in range(length)]

            # Ensure minimum characters per type
            if min_characters_per_type:
                for charset in character_sets:
                    filtered_charset = (
                        "".join(c for c in charset if c not in SIMILAR_CHARS)
                        if exclude_similar
                        else charset
                    )
                    if not filtered_charset:
                        continue

                    existing_count = sum(1 for c in password if c in filtered_charset)
                    needed = max(0, min_characters_per_type - existing_count)

                    for _ in range(needed):
                        candidate_positions = [
                            i
                            for i in range(length)
                            if (
                                not no_repeats
                                or (i == 0 or password[i - 1] not in filtered_charset)
                                and (
                                    i == length - 1
                                    or password[i + 1] not in filtered_charset
                                )
                            )
                        ]

                        if not candidate_positions:
                            raise ValueError(
                                "Cannot satisfy both minimum characters and no-repeats requirements"
                            )

                        pos = secrets.choice(candidate_positions)
                        password[pos] = secrets.choice(filtered_charset)

            secrets.SystemRandom().shuffle(password)
            return "".join(password)

        except ValueError:
            if attempt == MAX_GENERATION_ATTEMPTS - 1:
                raise ValueError(
                    f"Failed to generate password after {MAX_GENERATION_ATTEMPTS} attempts"
                )
            continue


def save_password(password: str, filename: str = PASSWORD_FILE) -> None:
    """Securely save password to file with restricted permissions."""
    try:
        file_path = Path(filename)
        with file_path.open("a") as f:
            f.write(password + "\n")
        file_path.chmod(0o600)
    except IOError as e:
        print(f"Error saving password: {e}", file=sys.stderr)
        raise


def show_password_history(filename: str = PASSWORD_FILE) -> None:
    """Display password generation history."""
    try:
        file_path = Path(filename)
        if not file_path.exists():
            print("No password history available")
            return

        with file_path.open("r") as f:
            passwords = f.read().splitlines()

        print("\nPassword History:")
        print("-" * 50)
        for idx, password in enumerate(reversed(passwords), 1):
            print(f"{idx}. {password}")
        print("-" * 50)

    except Exception as e:
        print(f"Error reading history: {e}", file=sys.stderr)


def main() -> None:
    # Custom formatter that shows example usage
    class CustomHelpFormatter(argparse.HelpFormatter):
        def _format_usage(self, usage, actions, groups, prefix):
            help_text = super()._format_usage(usage, actions, groups, prefix)
            help_text += "\nExample:\n        python password_generator.py --length 24 \\\n          "
            help_text += "--upper --lower --digits --symbols \\\n          "
            help_text += "--allowed-symbols @#$%% --min 2 --count 5 \\\n          "
            help_text += "--exclude-similar --no-repeats --no-save\n\n"
            return help_text

    parser = argparse.ArgumentParser(
        description="Generate strong random passwords.",
        formatter_class=CustomHelpFormatter,
        add_help=False,
    )

    # Add help option
    parser.add_argument(
        "-h", "--help", action="store_true", help="Show this help message and exit"
    )

    # Password generation arguments
    parser.add_argument(
        "-L",
        "--length",
        type=int,
        default=DEFAULT_PASSWORD_LENGTH,
        help=f"Length of the password (minimum: {MIN_PASSWORD_LENGTH})",
    )
    parser.add_argument(
        "-u", "--upper", action="store_true", help="Include uppercase letters"
    )
    parser.add_argument(
        "-l", "--lower", action="store_true", help="Include lowercase letters"
    )
    parser.add_argument("-d", "--digits", action="store_true", help="Include digits")
    parser.add_argument("-s", "--symbols", action="store_true", help="Include symbols")
    parser.add_argument(
        "-a",
        "--allowed-symbols",
        type=str,
        help="Specify which symbols are allowed (implies --symbols, e.g., @#$%%)",
    )
    parser.add_argument(
        "-m",
        "--min",
        type=int,
        dest="min_chars",
        default=1,
        help="Minimum characters from each selected type",
    )
    parser.add_argument(
        "-c", "--count", type=int, default=1, help="Number of passwords to generate"
    )
    parser.add_argument(
        "-e",
        "--exclude-similar",
        action="store_true",
        help="Exclude similar-looking characters (i, l, 1, L, o, 0, O)",
    )
    parser.add_argument(
        "-r",
        "--no-repeats",
        action="store_true",
        help="Prevent consecutive duplicate characters",
    )
    parser.add_argument(
        "-n", "--no-save", action="store_true", help="Do not save the password to file"
    )
    parser.add_argument(
        "-H",
        "--show-history",
        action="store_true",
        help="Show password generation history",
    )

    # If no arguments provided, show help
    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(0)

    args = parser.parse_args()

    if args.help:
        parser.print_help()
        sys.exit(0)

    # Automatically enable symbols if allowed-symbols is specified
    if args.allowed_symbols:
        args.symbols = True

    if args.show_history:
        show_password_history()
        sys.exit(0)

    try:
        for i in range(args.count):
            password = generate_password(
                args.length,
                args.upper,
                args.lower,
                args.digits,
                args.symbols,
                args.min_chars,
                args.exclude_similar,
                args.allowed_symbols,
                args.no_repeats,
            )
            print(f"Generated Password {i+1}: {password}")

            if not args.no_save:
                save_password(password)

        if not args.no_save and args.count > 0:
            print(f"Passwords securely saved to {PASSWORD_FILE}")
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
