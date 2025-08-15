import secrets
import string
import argparse
from pathlib import Path
import sys
from typing import Optional

DEFAULT_PASSWORD_LENGTH = 12
MIN_PASSWORD_LENGTH = 8
PASSWORD_FILE = ".passwordlist.txt"

def generate_password(
    length: int,
    use_upper: bool,
    use_lower: bool,
    use_digits: bool,
    use_symbols: bool,
    min_characters_per_type: Optional[int] = None
) -> str:
    """Generate a cryptographically secure random password."""
    character_sets = []
    if use_upper:
        character_sets.append(string.ascii_uppercase)
    if use_lower:
        character_sets.append(string.ascii_lowercase)
    if use_digits:
        character_sets.append(string.digits)
    if use_symbols:
        character_sets.append(string.punctuation)

    if not character_sets:
        raise ValueError("At least one character type must be selected.")

    if length < MIN_PASSWORD_LENGTH:
        print(f"Warning: Password length increased to minimum of {MIN_PASSWORD_LENGTH} characters")
        length = MIN_PASSWORD_LENGTH

    all_chars = ''.join(character_sets)
    password = [secrets.choice(all_chars) for _ in range(length)]

    if min_characters_per_type:
        for charset in character_sets:
            for _ in range(min_characters_per_type):
                password[secrets.randbelow(length)] = secrets.choice(charset)

    secrets.SystemRandom().shuffle(password)
    return ''.join(password)

def save_password(password: str, filename: str = PASSWORD_FILE) -> None:
    """Securely save password to file with restricted permissions."""
    try:
        file_path = Path(filename)
        with file_path.open('a') as f:
            f.write(password + '\n')
        file_path.chmod(0o600)
    except IOError as e:
        print(f"Error saving password: {e}", file=sys.stderr)
        raise

def main() -> None:
    # Custom formatter that shows example usage
    class CustomHelpFormatter(argparse.HelpFormatter):
        def _format_usage(self, usage, actions, groups, prefix):
            return super()._format_usage(usage, actions, groups, prefix) + \
                "\nexample: python3 password_generator.py --length 24 --upper --lower --digits --symbols --min-chars 2 --no-save\n\n\n"

    parser = argparse.ArgumentParser(
        description='Generate a strong random password.',
        formatter_class=CustomHelpFormatter,
        add_help=False  # We'll add help manually to control behavior
    )
    
    # Add help option that shows help when no args are provided
    parser.add_argument(
        '-h', '--help',
        action='store_true',
        help='Show this help message and exit'
    )
    
    # Other arguments
    parser.add_argument(
        '-l', '--length',
        type=int,
        default=DEFAULT_PASSWORD_LENGTH,
        help=f'Length of the password (minimum: {MIN_PASSWORD_LENGTH})'
    )
    parser.add_argument(
        '--upper',
        action='store_true',
        help='Include uppercase letters'
    )
    parser.add_argument(
        '--lower',
        action='store_true',
        help='Include lowercase letters'
    )
    parser.add_argument(
        '--digits',
        action='store_true',
        help='Include digits'
    )
    parser.add_argument(
        '--symbols',
        action='store_true',
        help='Include symbols'
    )
    parser.add_argument(
        '--min-chars',
        type=int,
        default=1,
        help='Minimum characters from each selected type'
    )
    parser.add_argument(
        '--no-save',
        action='store_true',
        help='Do not save the password to file'
    )

    args = parser.parse_args()

    # Show help if no arguments are provided or if help is explicitly requested
    if len(sys.argv) == 1 or args.help:
        parser.print_help()
        sys.exit(0)

    try:
        password = generate_password(
            args.length,
            args.upper,
            args.lower,
            args.digits,
            args.symbols,
            args.min_chars
        )
        print(f'Generated Password: {password}')

        if not args.no_save:
            save_password(password)
            print(f"Password securely saved to {PASSWORD_FILE}")
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()
