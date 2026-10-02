"""
Interactive REPL for Secure Password Generator.

Provides a ``cmd.Cmd`` shell (``PwgenShell``) with guided commands for
password generation, vault browsing, and health reporting.  CLI-style
commands (``generate``, ``save``, ``history``, ``delete``, ``cleanup``)
accept the same flags as the non-interactive CLI.
"""

import argparse
import base64
import cmd
import json
import shlex
from collections import Counter
from types import SimpleNamespace

import secure_password_generator.constants as _constants
from secure_password_generator.clipboard import (
    copy_to_clipboard,
    schedule_clipboard_clear,
)
from secure_password_generator.config import CharsetConfig
from secure_password_generator.crypto import (
    _FINAL_KEY_CACHE,
    _KEY_CACHE,
    cleanup_files,
    decrypt_data,
    get_encryption_key,
    resolve_master_password,
)
from secure_password_generator.generator import (
    calculate_password_strength,
    compute_charset_size,
    format_strength_inline,
    format_strength_meter,
    generate_password,
)
from secure_password_generator.history import (
    delete_entry_by_index,
    save_password,
    show_password_history,
    update_entry_metadata,
)

FULL_CFG = CharsetConfig(
    use_upper=True,
    use_lower=True,
    use_digits=True,
    use_symbols=True,
)

PAGE_SIZE = 5


# ── Argument parsers for CLI-style commands ──────────────────────────────


def _generate_parser() -> argparse.ArgumentParser:
    """Build the ``generate`` command parser."""
    p = argparse.ArgumentParser(
        prog="generate",
        description="Generate passwords with CLI flags.",
        exit_on_error=False,
    )
    p.add_argument("-F", "--full", action="store_true",
                   help="All character types + no-repeats")
    p.add_argument("-L", "--length", type=int, default=12,
                   help="Password length (default: 12)")
    p.add_argument("-c", "--count", type=int, default=1,
                   help="Number of passwords (default: 1)")
    p.add_argument("-u", "--upper", action="store_true",
                   help="Include uppercase letters")
    p.add_argument("-l", "--lower", action="store_true",
                   help="Include lowercase letters")
    p.add_argument("-d", "--digits", action="store_true",
                   help="Include digits")
    p.add_argument("-s", "--symbols", action="store_true",
                   help="Include symbols")
    p.add_argument("-a", "--allowed-symbols", type=str,
                   help="Specify allowed symbols (implies --symbols)")
    p.add_argument("-x", "--latin-ext", action="store_true",
                   help="Include Latin-1 extended characters")
    p.add_argument("-b", "--blank", action="store_true",
                   help="Include blank (space) character")
    p.add_argument("-r", "--no-repeats", action="store_true",
                   help="Prevent consecutive duplicate characters")
    p.add_argument("-e", "--exclude-similar", action="store_true",
                   help="Exclude similar-looking characters")
    p.add_argument("-m", "--min", type=int, dest="min_chars", default=1,
                   help="Minimum characters per selected type")
    p.add_argument("-p", "--pattern", type=str,
                   help="Generate from pattern (l/u/d/s/b/*)")
    p.add_argument("-n", "--no-save", action="store_true",
                   help="Just print (do not prompt to save)")
    p.add_argument("--label", type=str, help="Label for saved passwords")
    p.add_argument("--category", type=str, help="Category for saved passwords")
    p.add_argument("--tags", type=str,
                   help="Comma-separated tags for saved passwords")
    return p


def _save_parser() -> argparse.ArgumentParser:
    """Build the ``save`` command parser."""
    p = argparse.ArgumentParser(
        prog="save",
        description="Save the last generated password to the vault.",
        exit_on_error=False,
    )
    p.add_argument("--label", type=str, help="Label for this password")
    p.add_argument("--category", type=str, help="Category")
    p.add_argument("--tags", type=str,
                   help="Comma-separated tags")
    return p


def _history_parser() -> argparse.ArgumentParser:
    """Build the ``history`` command parser."""
    p = argparse.ArgumentParser(
        prog="history",
        description="Show / search / filter vault history.",
        exit_on_error=False,
    )
    p.add_argument("--search", type=str, help="Search term")
    p.add_argument("--filter-strength", type=int,
                   help="Minimum strength score")
    p.add_argument("--filter-category", type=str, help="Category filter")
    p.add_argument("--since", type=str, help="Date filter (YYYY-MM-DD)")
    p.add_argument("--limit", type=int, help="Max entries to display")
    return p


def _label_parser() -> argparse.ArgumentParser:
    """Build the ``label`` command parser."""
    p = argparse.ArgumentParser(
        prog="label",
        description="Update metadata on an existing vault entry.",
        exit_on_error=False,
    )
    p.add_argument("index", type=int, help="Entry index (newest first)")
    p.add_argument("--label", type=str, help="New label")
    p.add_argument("--category", type=str, help="New category")
    p.add_argument("--tags", type=str, help="Comma-separated tags")
    return p


def _decrypt_vault(key: bytes) -> list[dict]:
    """Decrypt every vault entry and return as a list of dicts."""
    filename = _constants.PASSWORD_FILE
    if not filename.exists():
        return []
    with open(filename, "rb") as fh:
        lines = [line.strip() for line in fh if line.strip()]
    lines.reverse()
    entries: list[dict] = []
    for line in lines:
        try:
            blob = base64.b64decode(line, validate=True)
            rec = json.loads(decrypt_data(blob, key))
            entries.append(rec)
        except Exception:
            continue
    return entries


class PwgenShell(cmd.Cmd):
    """Interactive REPL for guided password generation."""

    intro = (
        "Welcome to Secure Password Generator — interactive mode.\n"
        "Type 'help' for available commands.\n"
    )
    prompt = "pwgen> "
    use_rawinput = True

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self._key: bytes | None = None
        self._last_password: str | None = None
        self._last_pool_size: int | None = None

    def _require_key(self) -> bytes:
        """Resolve and cache the encryption key for the session."""
        if self._key is not None:
            return self._key
        args = SimpleNamespace(
            master_password=None,
            master_password_file=None,
            unlock=False,
        )
        master_pw = resolve_master_password(args)
        self._key = get_encryption_key(master_pw)
        return self._key

    # ── quick ────────────────────────────────────────────────────────

    def do_quick(self, arg: str) -> None:
        """Generate a password with all character types.  Usage: quick [LENGTH]"""
        length = 24
        if arg.strip():
            try:
                length = int(arg.strip())
            except ValueError:
                print(f"Invalid length: {arg.strip()}")
                return

        self._generate_and_prompt(length, FULL_CFG)

    def _generate_and_prompt(self, length: int, cfg: CharsetConfig) -> None:
        """Generate a password and show the action prompt."""
        pool_size = compute_charset_size(cfg)
        password = generate_password(length=length, cfg=cfg, no_repeats=True)
        strength = calculate_password_strength(password, charset_size=pool_size)
        inline = format_strength_inline(strength)

        self._last_password = password
        self._last_pool_size = pool_size

        print(f"\n  {password}  {inline}\n")

        while True:
            try:
                choice = input("[c]opy  [r]egenerate  [s]ave  [q]uit: ").strip().lower()
            except EOFError:
                print()
                return

            if choice == "c":
                if copy_to_clipboard(password):
                    print("[+] Copied to clipboard")
                    schedule_clipboard_clear()
                else:
                    print("[!] Clipboard not available")
            elif choice == "r":
                password = generate_password(length=length, cfg=cfg, no_repeats=True)
                strength = calculate_password_strength(password, charset_size=pool_size)
                inline = format_strength_inline(strength)
                self._last_password = password
                self._last_pool_size = pool_size
                print(f"\n  {password}  {inline}\n")
            elif choice == "s":
                try:
                    label = input("Label [Unnamed]: ").strip() or None
                    category = input("Category [General]: ").strip() or None
                    tags_raw = input("Tags (comma-separated) []: ").strip()
                    tags = (
                        [t.strip() for t in tags_raw.split(",") if t.strip()]
                        if tags_raw
                        else None
                    )
                    key = self._require_key()
                    save_password(
                        password, key=key, label=label,
                        category=category, tags=tags,
                        charset_size=pool_size,
                    )
                    print("[+] Password saved to vault")
                except Exception as exc:
                    print(f"[!] Save failed: {exc}")
                return
            elif choice == "q":
                return
            else:
                print("Please choose c, r, s, or q.")

    # ── new ──────────────────────────────────────────────────────────

    def do_new(self, _arg: str) -> None:
        """Guided wizard to generate a custom password."""
        try:
            length_str = input("Length [24]: ").strip()
            length = int(length_str) if length_str else 24

            upper = input("Include uppercase? [Y/n]: ").strip().lower() != "n"
            lower = input("Include lowercase? [Y/n]: ").strip().lower() != "n"
            digits = input("Include digits? [Y/n]: ").strip().lower() != "n"
            symbols = input("Include symbols? [Y/n]: ").strip().lower() != "n"
        except EOFError:
            print("\nWizard cancelled.")
            return

        cfg = CharsetConfig(
            use_upper=upper,
            use_lower=lower,
            use_digits=digits,
            use_symbols=symbols,
        )

        if not any([upper, lower, digits, symbols]):
            print("[!] At least one character type must be selected.")
            return

        self._generate_and_prompt(length, cfg)

    # ── browse ───────────────────────────────────────────────────────

    def do_browse(self, _arg: str) -> None:
        """Browse saved passwords (paginated)."""
        try:
            key = self._require_key()
        except Exception as exc:
            print(f"[!] {exc}")
            return

        entries = _decrypt_vault(key)
        if not entries:
            print("Vault is empty.")
            return

        page = 0
        total_pages = (len(entries) + PAGE_SIZE - 1) // PAGE_SIZE

        while True:
            start = page * PAGE_SIZE
            end = min(start + PAGE_SIZE, len(entries))
            print(f"\n--- Page {page + 1}/{total_pages} "
                  f"({len(entries)} entries) ---\n")
            for idx in range(start, end):
                e = entries[idx]
                score = e.get("strength", 0)
                meter = format_strength_inline(score)
                label = e.get("label", "N/A")
                print(f"  {idx + 1}. {label}  {meter}")
            print()

            try:
                choice = input(
                    "[n]ext  [p]revious  [v]iew #  [s]earch  [q]uit: "
                ).strip().lower()
            except EOFError:
                print()
                return

            if choice == "n":
                if page < total_pages - 1:
                    page += 1
                else:
                    print("Already on the last page.")
            elif choice == "p":
                if page > 0:
                    page -= 1
                else:
                    print("Already on the first page.")
            elif choice.startswith("v"):
                parts = choice.split()
                num_str = parts[1] if len(parts) > 1 else ""
                if not num_str:
                    try:
                        num_str = input("Entry number: ").strip()
                    except EOFError:
                        print()
                        return
                try:
                    num = int(num_str)
                    if 1 <= num <= len(entries):
                        self._view_entry(entries[num - 1])
                    else:
                        print(f"Invalid entry. Valid range: 1-{len(entries)}")
                except ValueError:
                    print("Invalid number.")
            elif choice == "s":
                try:
                    term = input("Search term: ").strip().lower()
                except EOFError:
                    print()
                    return
                if term:
                    matches = [
                        e for e in entries
                        if term in e.get("label", "").lower()
                        or term in e.get("category", "").lower()
                        or term in " ".join(e.get("tags", [])).lower()
                    ]
                    if matches:
                        print(f"\n{len(matches)} match(es):\n")
                        for i, m in enumerate(matches, 1):
                            score = m.get("strength", 0)
                            meter = format_strength_inline(score)
                            print(f"  {i}. {m.get('label', 'N/A')}  {meter}")
                    else:
                        print("No matches found.")
            elif choice == "q":
                return
            else:
                print("Please choose n, p, v, s, or q.")

    def _view_entry(self, entry: dict) -> None:
        """Display full details for a single vault entry."""
        print(f"\n  Label:    {entry.get('label', 'N/A')}")
        print(f"  Password: {entry.get('password', '?')}")
        score = entry.get("strength", 0)
        print(f"  Strength: {format_strength_meter(score)}")
        print(f"  Category: {entry.get('category', 'N/A')}")
        tags = entry.get("tags", [])
        if tags:
            print(f"  Tags:     {', '.join(tags)}")
        print(f"  Created:  {entry.get('timestamp', '?')}")
        print()

        while True:
            try:
                choice = input("[c]opy  [b]ack: ").strip().lower()
            except EOFError:
                print()
                return
            if choice == "c":
                pw = entry.get("password", "")
                if copy_to_clipboard(pw):
                    print("[+] Copied to clipboard")
                    schedule_clipboard_clear()
                else:
                    print("[!] Clipboard not available")
            elif choice == "b":
                return
            else:
                print("Please choose c or b.")

    # ── health ───────────────────────────────────────────────────────

    def do_health(self, _arg: str) -> None:
        """Show vault health report."""
        try:
            key = self._require_key()
        except Exception as exc:
            print(f"[!] {exc}")
            return

        entries = _decrypt_vault(key)
        if not entries:
            print("Vault is empty — nothing to report.")
            return

        scores = [e.get("strength", 0) for e in entries]
        labels = [e.get("label", "N/A") for e in entries]
        timestamps = [e.get("timestamp", "") for e in entries]

        print(f"\n  Total passwords: {len(entries)}")

        dist = Counter(scores)
        print("\n  Score distribution:")
        for score in sorted(dist, reverse=True):
            meter = format_strength_meter(score)
            print(f"    {meter}: {dist[score]}")

        if timestamps:
            print(f"\n  Oldest entry: {timestamps[-1]}")

        dup_labels = [
            lbl for lbl, cnt in Counter(labels).items()
            if cnt > 1 and lbl != "Unnamed"
        ]
        if dup_labels:
            print(f"\n  Duplicate labels: {', '.join(dup_labels)}")

        weak = sum(1 for s in scores if s < 5)
        if weak:
            print(f"\n  ⚠ {weak} password(s) scored below 5/10 "
                  "— consider regenerating.")
        else:
            print("\n  ✓ All passwords score 5/10 or above.")
        print()

    # ── generate (CLI-style) ───────────────────────────────────────────

    def do_generate(self, arg: str) -> None:
        """Generate passwords with CLI flags.  Usage: generate [options]

        Examples:
          generate -F -L 20
          generate -u -l -d -L 16 -c 3
          generate --pattern 'uullddss'
        """
        parser = _generate_parser()
        try:
            opts = parser.parse_args(shlex.split(arg))
        except (SystemExit, argparse.ArgumentError) as exc:
            if isinstance(exc, argparse.ArgumentError):
                print(f"generate: {exc}")
            return

        if opts.full:
            opts.upper = True
            opts.lower = True
            opts.digits = True
            opts.symbols = True
            opts.no_repeats = True

        if opts.allowed_symbols:
            opts.symbols = True

        cfg = CharsetConfig(
            use_upper=opts.upper,
            use_lower=opts.lower,
            use_digits=opts.digits,
            use_symbols=opts.symbols,
            allowed_symbols=opts.allowed_symbols,
            exclude_similar=opts.exclude_similar,
            blank=opts.blank,
            latin_ext=opts.latin_ext,
        )

        pool_size = compute_charset_size(cfg)
        scores: list[int] = []
        save = not opts.no_save
        key: bytes | None = None

        tags_list = (
            [t.strip() for t in opts.tags.split(",") if t.strip()]
            if opts.tags
            else None
        )

        if save:
            try:
                key = self._require_key()
            except Exception as exc:
                print(f"[!] {exc}")
                return

        for i in range(opts.count):
            password = generate_password(
                length=opts.length,
                cfg=cfg,
                min_characters_per_type=opts.min_chars,
                no_repeats=opts.no_repeats,
                pattern=opts.pattern,
            )
            strength = calculate_password_strength(
                password, charset_size=pool_size,
            )
            scores.append(strength)
            inline = format_strength_inline(strength)
            print(f"Generated Password {i + 1}: {password}  {inline}")

            self._last_password = password
            self._last_pool_size = pool_size

            if save and key is not None:
                save_password(
                    password,
                    key=key,
                    label=opts.label,
                    category=opts.category,
                    tags=tags_list,
                    charset_size=pool_size,
                )

        if opts.count > 0:
            count_label = "password" if opts.count == 1 else "passwords"
            print(
                f"\nStrength Summary: {opts.count} {count_label} generated"
            )
            score_counts = Counter(scores)
            for score in sorted(score_counts, reverse=True):
                meter = format_strength_meter(score)
                count = score_counts[score]
                pw_label = "password" if count == 1 else "passwords"
                print(f"  {meter}: {count} {pw_label}")

            if save:
                print(f"[+] Passwords securely saved to {_constants.PASSWORD_FILE}")

    # ── save (CLI-style) ─────────────────────────────────────────────

    def do_save(self, arg: str) -> None:
        """Save the last generated password.

        Usage: save [--label L] [--category C] [--tags T]
        """
        if self._last_password is None:
            print("No password to save. Run 'generate' or 'quick' first.")
            return

        parser = _save_parser()
        try:
            opts = parser.parse_args(shlex.split(arg))
        except (SystemExit, argparse.ArgumentError) as exc:
            if isinstance(exc, argparse.ArgumentError):
                print(f"save: {exc}")
            return

        tags = (
            [t.strip() for t in opts.tags.split(",") if t.strip()]
            if opts.tags
            else None
        )

        try:
            key = self._require_key()
            save_password(
                self._last_password,
                key=key,
                label=opts.label,
                category=opts.category,
                tags=tags,
                charset_size=self._last_pool_size,
            )
            print("[+] Password saved to vault")
        except Exception as exc:
            print(f"[!] Save failed: {exc}")

    # ── history (CLI-style) ──────────────────────────────────────────

    def do_history(self, arg: str) -> None:
        """Show vault history.

        Usage: history [--search S] [--filter-strength N] [--limit N]
        """
        parser = _history_parser()
        try:
            opts = parser.parse_args(shlex.split(arg))
        except (SystemExit, argparse.ArgumentError) as exc:
            if isinstance(exc, argparse.ArgumentError):
                print(f"history: {exc}")
            return

        try:
            key = self._require_key()
            show_password_history(
                key,
                search=opts.search,
                filter_strength=opts.filter_strength,
                filter_category=opts.filter_category,
                since=opts.since,
                limit=opts.limit,
            )
        except Exception as exc:
            print(f"[!] {exc}")

    # ── delete (CLI-style) ───────────────────────────────────────────

    def do_delete(self, arg: str) -> None:
        """Delete a vault entry by index.  Usage: delete <INDEX>"""
        arg = arg.strip()
        if not arg:
            print("Usage: delete <INDEX>")
            return

        try:
            index = int(arg)
        except ValueError:
            print(f"Invalid index: {arg}")
            return

        try:
            key = self._require_key()
            delete_entry_by_index(index, key)
        except Exception as exc:
            print(f"[!] {exc}")

    # ── label (CLI-style) ────────────────────────────────────────────

    def do_label(self, arg: str) -> None:
        """Update metadata on a vault entry by index.

        Usage: label <INDEX> [--label L] [--category C] [--tags T]
        """
        parser = _label_parser()
        try:
            opts = parser.parse_args(shlex.split(arg))
        except (SystemExit, argparse.ArgumentError, ValueError) as exc:
            if isinstance(exc, argparse.ArgumentError):
                print(f"label: {exc}")
            return

        tags = (
            [t.strip() for t in opts.tags.split(",") if t.strip()]
            if opts.tags
            else None
        )

        try:
            key = self._require_key()
            update_entry_metadata(
                opts.index,
                key,
                label=opts.label,
                category=opts.category,
                tags=tags,
            )
        except Exception as exc:
            print(f"[!] {exc}")

    # ── cleanup (CLI-style) ──────────────────────────────────────────

    def do_cleanup(self, _arg: str) -> None:
        """Securely delete all vault files.  Usage: cleanup"""
        try:
            confirm = input(
                "Are you sure? This will securely delete all vault "
                "files. [y/N]: "
            ).strip().lower()
        except EOFError:
            print("\nCleanup cancelled.")
            return

        if confirm != "y":
            print("Cleanup cancelled.")
            return

        cleanup_files()
        self._key = None
        _KEY_CACHE.clear()
        _FINAL_KEY_CACHE.clear()
        import secure_password_generator.crypto as _crypto
        _crypto._SESSION_TOKEN = None
        print("[+] Session key cleared")

    # ── clear ────────────────────────────────────────────────────────

    def do_clear(self, _arg: str) -> None:
        """Clear the terminal screen."""
        import os
        os.system("clear" if os.name != "nt" else "cls")

    # ── quit / exit / EOF ────────────────────────────────────────────

    def do_quit(self, _arg: str) -> bool:
        """Exit interactive mode."""
        self._cleanup()
        print("Goodbye.")
        return True

    def do_exit(self, arg: str) -> bool:
        """Exit interactive mode."""
        return self.do_quit(arg)

    def do_EOF(self, _arg: str) -> bool:
        """Exit on Ctrl+D."""
        print()
        self._cleanup()
        return True

    def _cleanup(self) -> None:
        """Clear cached crypto state."""
        self._key = None
        _KEY_CACHE.clear()
        _FINAL_KEY_CACHE.clear()
        import secure_password_generator.crypto as _crypto
        _crypto._SESSION_TOKEN = None

    # ── error handling ───────────────────────────────────────────────

    def default(self, line: str) -> None:
        """Handle unknown commands."""
        print(f"Unknown command: {line}")
        print("Type 'help' for available commands.")

    def emptyline(self) -> None:
        """Do nothing on empty input."""
