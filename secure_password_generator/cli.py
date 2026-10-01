# PYTHON_ARGCOMPLETE_OK
"""
Command-line interface for Secure Password Generator.
"""

import argparse
import sys

import argcomplete
from argcomplete.completers import FilesCompleter

import secure_password_generator.constants as _constants
from secure_password_generator import __version__
from secure_password_generator.clipboard import (
    copy_to_clipboard,
    schedule_clipboard_clear,
)
from secure_password_generator.config import CharsetConfig, ConfigError, load_config
from secure_password_generator.constants import (
    CLIPBOARD_CLEAR_SECONDS,
    DEFAULT_PASSWORD_LENGTH,
    MIN_PASSWORD_LENGTH,
)
from secure_password_generator.crypto import (
    cleanup_files,
    get_encryption_key,
    is_master_password_enabled,
    resolve_master_password,
    set_master_password,
)
from secure_password_generator.generator import (
    calculate_password_strength,
    compute_charset_size,
    format_strength_meter,
    generate_password,
)
from secure_password_generator.history import (
    delete_entry_by_index,
    save_password,
    show_password_history,
)
from secure_password_generator.utils import configure_logging

# ── Argument parser ──────────────────────────────────────────────────────


def create_argument_parser() -> argparse.ArgumentParser:
    """Create and configure the argument parser."""

    class CustomHelpFormatter(argparse.HelpFormatter):
        def _format_usage(self, usage, actions, groups, prefix):
            help_text = super()._format_usage(
                usage, actions, groups, prefix
            )
            help_text += "\nExamples:\n"
            help_text += (
                "  # Generate strong password with all character types\n"
            )
            help_text += "  pwgen -F -L 24\n\n"
            help_text += (
                "  # Generate password from pattern and copy to clipboard\n"
            )
            help_text += (
                "  pwgen --pattern 'llbuubddbss' --no-save-history"
                " --clipboard\n\n"
            )
            help_text += (
                "  # Generate multiple passwords with custom symbols\n"
            )
            help_text += (
                "  pwgen -n -L 30 -r -e -u -l -d -b -a '!@#$' -c 3 -m 3\n\n"
            )
            help_text += (
                "  # Generate password using config file defaults\n"
            )
            help_text += "  pwgen -f config.yaml\n\n"
            help_text += "  # Config file defaults with CLI override\n"
            help_text += "  pwgen -f config.json -L 32\n\n\n"
            return help_text

    parser = argparse.ArgumentParser(
        description="Generate strong random passwords.",
        formatter_class=CustomHelpFormatter,
        add_help=False,
    )

    basic_group = parser.add_argument_group("Basic Options")
    char_group = parser.add_argument_group("Character Type Options")
    advanced_group = parser.add_argument_group("Advanced Options")
    organizing_group = parser.add_argument_group(
        "Password Organization Options"
    )
    filter_group = parser.add_argument_group(
        "History Search & Filter Options"
    )
    file_group = parser.add_argument_group("File Operations")

    # Basic options
    basic_group.add_argument(
        "-h", "--help", action="store_true",
        help="Show this help message and exit",
    )
    basic_group.add_argument(
        "-V", "--version", action="version",
        version=f"%(prog)s {__version__}",
    )
    basic_group.add_argument(
        "-P", "--passphrase", type=str,
        help=(
            "Use a custom passphrase instead of generating a secure "
            "password (supersedes other options)"
        ),
    )
    basic_group.add_argument(
        "-L", "--length", type=int, default=DEFAULT_PASSWORD_LENGTH,
        help=f"Password length (minimum: {MIN_PASSWORD_LENGTH})",
    )
    basic_group.add_argument(
        "-c", "--count", type=int, default=1,
        help="Number of passwords to generate",
    )
    config_action = basic_group.add_argument(
        "-f", "--config", type=str, metavar="FILE",
        help=(
            "Load defaults from a YAML or JSON config file "
            "(CLI args override config values)"
        ),
    )
    config_action.completer = FilesCompleter(["yaml", "yml", "json"])
    basic_group.add_argument(
        "-X", "--clipboard", action="store_true",
        help="Copy password to clipboard",
    )
    basic_group.add_argument(
        "-U", "--unlock", action="store_true",
        help=(
            "Explicitly unlock vault with master password "
            "(auto-prompts when master password is configured)"
        ),
    )
    basic_group.add_argument(
        "--master-password", type=str, metavar="PASSWORD",
        help=(
            "Master password for scripting/CI "
            "(exposes password in process lists; prefer -U)"
        ),
    )
    basic_group.add_argument(
        "--master-password-file", type=str, metavar="FILE",
        help=(
            "Read master password from a file "
            "(first line is used; file should be chmod 600)"
        ),
    )
    basic_group.add_argument(
        "--set-master-password", action="store_true",
        help=(
            "Configure or change the master password and re-encrypt "
            "the vault"
        ),
    )
    basic_group.add_argument(
        "-v", "--verbose", action="store_true",
        help="Enable verbose (debug) output",
    )
    basic_group.add_argument(
        "--quiet", action="store_true",
        help="Suppress warnings; show only errors and results",
    )

    # Character type options
    char_group.add_argument(
        "-F", "--full", action="store_true",
        help=(
            "Use all character types (upper, lower, digits, symbols) "
            "and enable no-repeats"
        ),
    )
    char_group.add_argument(
        "-u", "--upper", action="store_true",
        help="Include uppercase letters",
    )
    char_group.add_argument(
        "-l", "--lower", action="store_true",
        help="Include lowercase letters",
    )
    char_group.add_argument(
        "-d", "--digits", action="store_true",
        help="Include digits",
    )
    char_group.add_argument(
        "-s", "--symbols", action="store_true",
        help="Include symbols",
    )
    char_group.add_argument(
        "-a", "--allowed-symbols", type=str,
        help="Specify allowed symbols (implies --symbols, e.g., @#$%%)",
    )
    char_group.add_argument(
        "-b", "--blank", action="store_true",
        help=(
            "Include blank (space) character "
            "(never placed as first or last character)"
        ),
    )
    char_group.add_argument(
        "-p", "--pattern", type=str,
        help=(
            "Generate password from pattern "
            "(l=lower, u=upper, d=digit, s=symbol, b=blank, *=any)"
        ),
    )
    char_group.add_argument(
        "-x", "--latin-ext", action="store_true",
        help=(
            "Include Latin-1 Supplement characters "
            "(accented letters, symbols)"
        ),
    )

    # Password organization options
    organizing_group.add_argument(
        "--label", type=str,
        help="Label/name for this password (e.g., 'Gmail Account')",
    )
    organizing_group.add_argument(
        "--category", type=str,
        help="Category for this password (e.g., 'Email', 'Banking')",
    )
    organizing_group.add_argument(
        "--tags", type=str,
        help="Comma-separated tags (e.g., 'work,important,2fa')",
    )

    # Advanced options
    advanced_group.add_argument(
        "-m", "--min", type=int, dest="min_chars", default=1,
        help="Minimum characters from each selected type",
    )
    advanced_group.add_argument(
        "-e", "--exclude-similar", action="store_true",
        help="Exclude similar-looking characters (i, l, 1, L, o, 0, O)",
    )
    advanced_group.add_argument(
        "-r", "--no-repeats", action="store_true",
        help="Prevent consecutive duplicate characters",
    )

    # History search & filter options
    filter_group.add_argument(
        "--search", type=str,
        help="Search history by label, category, or tags",
    )
    filter_group.add_argument(
        "--filter-strength", type=int,
        help="Show only passwords with strength >= this value",
    )
    filter_group.add_argument(
        "--filter-category", type=str,
        help="Show only passwords in this category",
    )
    filter_group.add_argument(
        "--since", type=str,
        help="Show passwords created since date (YYYY-MM-DD)",
    )
    filter_group.add_argument(
        "--delete-entry", type=int,
        help="Delete specific entry by index number",
    )

    # File operations
    file_group.add_argument(
        "-n", "--no-save-history", action="store_false",
        dest="save_history", default=True,
        help="Do not save the password to history",
    )
    file_group.add_argument(
        "-H", "--show-history", action="store_true",
        help="Show password generation history",
    )
    file_group.add_argument(
        "-C", "--cleanup", action="store_true",
        help="Clean up password and key files",
    )
    file_group.add_argument(
        "--limit", type=int,
        help="Limit number of history entries to display",
    )

    return parser


# ── Main entry point ─────────────────────────────────────────────────────


def main() -> None:
    """Main entry point for the password generator CLI."""
    parser = create_argument_parser()
    argcomplete.autocomplete(parser)

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(0)

    args = parser.parse_args()

    # Configure logging early
    configure_logging(verbose=args.verbose, quiet=args.quiet)

    # Apply config file defaults (CLI args take precedence)
    if args.config:
        try:
            config = load_config(args.config)
        except ConfigError as exc:
            print(f"[!] {exc}", file=sys.stderr)
            sys.exit(1)
        defaults = parser.parse_args([])
        for key, value in config.items():
            if hasattr(args, key) and getattr(args, key) == getattr(
                defaults, key
            ):
                setattr(args, key, value)

    if args.help:
        parser.print_help()
        sys.exit(0)

    # ── Master-password setup ───────────────────────────────────────
    if args.set_master_password:
        try:
            new_pw = args.master_password
            current_pw = (
                args.master_password
                if is_master_password_enabled()
                else None
            )
            set_master_password(
                new_password=new_pw, current_password=current_pw
            )
        except Exception as exc:
            print(f"[!] Error: {exc}", file=sys.stderr)
            sys.exit(1)
        sys.exit(0)

    if args.cleanup:
        cleanup_files()
        sys.exit(0)

    def _require_key() -> bytes:
        """Resolve encryption key on demand for vault operations."""
        try:
            master_pw = resolve_master_password(args)
            return get_encryption_key(master_pw)
        except Exception as exc:
            print(f"[!] Error: {exc}", file=sys.stderr)
            sys.exit(1)

    if args.show_history:
        show_password_history(
            key=_require_key(),
            limit=args.limit,
            search=args.search,
            filter_strength=args.filter_strength,
            filter_category=args.filter_category,
            since=args.since,
            use_table=True,
        )
        sys.exit(0)

    if args.delete_entry:
        delete_entry_by_index(args.delete_entry, key=_require_key())
        sys.exit(0)

    # ── Character-type flags ────────────────────────────────────────
    if args.full:
        args.upper = True
        args.lower = True
        args.digits = True
        args.symbols = True
        args.no_repeats = True

    if args.allowed_symbols:
        args.symbols = True

    tags: list[str] | None = None
    if args.tags:
        tags = [tag.strip() for tag in args.tags.split(",")]

    try:
        if args.passphrase:
            print("[ Custom Passphrase Mode ]")
            print(f"Using provided passphrase: {args.passphrase}")

            if args.save_history:
                save_password(
                    args.passphrase,
                    key=_require_key(),
                    label=args.label,
                    category=args.category,
                    tags=tags,
                )
                print(f"[+] Passphrase securely saved to {_constants.PASSWORD_FILE}")
            else:
                print(
                    "[*] Passphrase not saved "
                    "(--no-save-history flag was set)"
                )
            sys.exit(0)

        cfg = CharsetConfig(
            use_upper=args.upper,
            use_lower=args.lower,
            use_digits=args.digits,
            use_symbols=args.symbols,
            allowed_symbols=args.allowed_symbols,
            exclude_similar=args.exclude_similar,
            blank=args.blank,
            latin_ext=args.latin_ext,
        )

        pool_size = compute_charset_size(cfg)

        key: bytes | None = (
            _require_key() if args.save_history else None
        )

        for i in range(args.count):
            password = generate_password(
                length=args.length,
                cfg=cfg,
                min_characters_per_type=args.min_chars,
                no_repeats=args.no_repeats,
                pattern=args.pattern,
            )

            strength = calculate_password_strength(
                password, charset_size=pool_size
            )
            strength_display = format_strength_meter(strength)

            print(f"Generated Password {i + 1}: {password}")
            print(f"Strength: {strength_display}")

            if args.clipboard:
                if copy_to_clipboard(password):
                    print("[+] Password copied to clipboard")
                    schedule_clipboard_clear()
                    print(
                        f"Clipboard will auto-clear in "
                        f"{CLIPBOARD_CLEAR_SECONDS} seconds..."
                    )
                else:
                    print(
                        "[*] Could not copy to clipboard "
                        "(install pyperclip for better support)"
                    )

            if args.save_history and key is not None:
                save_password(
                    password,
                    key=key,
                    label=args.label,
                    category=args.category,
                    tags=tags,
                    charset_size=pool_size,
                )

        if args.save_history and args.count > 0:
            print(f"[+] Passwords securely saved to {_constants.PASSWORD_FILE}")
    except Exception as exc:
        print(f"[!] Error: {exc}", file=sys.stderr)
        sys.exit(1)
