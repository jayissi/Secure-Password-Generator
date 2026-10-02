"""
Vault CRUD operations, table formatting, and search/filter.
"""

import base64
import json
import logging
import unicodedata
from datetime import datetime
from pathlib import Path
from typing import Any

from tabulate import tabulate

import secure_password_generator.constants as _constants
from secure_password_generator.constants import (
    COLOR_RESET,
    DEFAULT_FILE_PERMISSIONS,
)
from secure_password_generator.crypto import (
    argon2id_hash,
    decrypt_data,
    encrypt_data,
)
from secure_password_generator.generator import (
    calculate_password_strength,
    format_strength_meter,
    get_strength_color,
)
from secure_password_generator.utils import (
    secure_delete_file,
    verify_file_permissions,
)

logger = logging.getLogger("secure_password_generator")


def format_history_table(entries: list[dict[str, Any]]) -> str:
    """Format password history as a table using ``tabulate``.

    Args:
        entries: List of password record dictionaries.

    Returns:
        Formatted table string.
    """
    if not entries:
        return "No entries to display."

    headers = ["#", "Label", "Password", "Strength", "Category", "Created"]
    rows: list[list[Any]] = []

    for idx, entry in enumerate(entries, 1):
        label = str(entry.get("label", "N/A"))
        password = str(entry.get("password", "?"))
        strength = entry.get("strength", 0)
        category = str(entry.get("category", "N/A"))
        timestamp = entry.get("timestamp", "?")

        try:
            dt = datetime.strptime(
                timestamp, "%a, %b %d, %Y %I:%M:%S:%f %p"
            )
            short_time = dt.strftime("%Y-%m-%d %H:%M")
        except ValueError:
            short_time = (
                timestamp[:16] if len(timestamp) > 16 else timestamp
            )

        color = get_strength_color(strength)
        colored_score = f"{color}{strength}/10{COLOR_RESET}"
        rows.append(
            [idx, label, password, colored_score, category, short_time]
        )

    return tabulate(rows, headers=headers, tablefmt="simple_grid")


def save_password(
    password: str,
    key: bytes,
    filename: Path | None = None,
    label: str | None = None,
    category: str | None = None,
    tags: list[str] | None = None,
    charset_size: int | None = None,
) -> None:
    """Securely save an encrypted password record with metadata."""
    password = unicodedata.normalize("NFC", password)
    if filename is None:
        filename = _constants.PASSWORD_FILE
    try:
        verify_file_permissions(filename)
        strength = calculate_password_strength(
            password, charset_size=charset_size
        )
        record = {
            "timestamp": datetime.now().strftime(
                "%a, %b %d, %Y %I:%M:%S:%f %p"
            ),
            "password": password,
            "strength": strength,
            "label": label or "Unnamed",
            "category": category or "General",
            "tags": tags or [],
            "argon2id": argon2id_hash(password),
        }
        plaintext = json.dumps(record, separators=(",", ":"))
        encrypted = encrypt_data(plaintext, key)
        line = base64.b64encode(encrypted) + b"\n"

        with open(filename, "ab") as f:
            f.write(line)
        filename.chmod(DEFAULT_FILE_PERMISSIONS)
    except Exception as exc:
        logger.error("Error saving password: %s", exc)
        raise


def show_password_history(
    key: bytes,
    filename: Path | None = None,
    limit: int | None = None,
    search: str | None = None,
    filter_strength: int | None = None,
    filter_category: str | None = None,
    since: str | None = None,
    use_table: bool = True,
) -> None:
    """Display password history with optional filtering."""
    if filename is None:
        filename = _constants.PASSWORD_FILE
    try:
        if not filename.exists():
            print("No password history available")
            return

        verify_file_permissions(filename)

        with open(filename, "rb") as f:
            entries = [line.strip() for line in f if line.strip()]
        entries.reverse()

        filtered_entries: list[dict[str, Any]] = []
        for line in entries:
            try:
                blob = base64.b64decode(line, validate=True)
                rec_json = decrypt_data(blob, key)
                rec = json.loads(rec_json)

                if search:
                    search_lower = search.lower()
                    if (
                        search_lower
                        not in rec.get("label", "").lower()
                        and search_lower
                        not in rec.get("category", "").lower()
                        and search_lower
                        not in " ".join(rec.get("tags", [])).lower()
                    ):
                        continue

                if (filter_strength is not None
                        and rec.get("strength", 0) < filter_strength):
                    continue

                if (filter_category
                        and rec.get("category", "").lower()
                        != filter_category.lower()):
                    continue

                if since:
                    try:
                        since_dt = datetime.strptime(since, "%Y-%m-%d")
                        entry_dt = datetime.strptime(
                            rec.get("timestamp", ""),
                            "%a, %b %d, %Y %I:%M:%S:%f %p",
                        )
                        if entry_dt < since_dt:
                            continue
                    except ValueError:
                        pass

                filtered_entries.append(rec)
            except Exception as exc:
                logger.debug("Skipping unreadable vault entry: %s", exc)
                continue

        if limit:
            filtered_entries = filtered_entries[:limit]

        if use_table:
            print("\n" + format_history_table(filtered_entries))
        else:
            print("\nPassword History:")
            print("-" * 80)
            for idx, entry in enumerate(filtered_entries, 1):
                timestamp = entry.get("timestamp", "?")
                password = entry.get("password", "?")
                strength = entry.get("strength", 0)
                strength_display = format_strength_meter(strength)
                label = entry.get("label", "N/A")
                category = entry.get("category", "N/A")
                tags = entry.get("tags", [])

                print(f"{idx}. Label: {label}")
                print(f"   Password: {password}")
                print(f"   Strength: {strength_display}")
                print(f"   Category: {category}")
                if tags:
                    print(f"   Tags: {', '.join(tags)}")
                print(f"   Timestamp: {timestamp}\n")
            print("-" * 80)
    except Exception as exc:
        logger.error("Error reading history: %s", exc)


def delete_entry_by_index(
    index: int,
    key: bytes,
    filename: Path | None = None,
) -> None:
    """Delete a specific entry by index with secure deletion.

    The encryption *key* is used to decrypt the target entry before
    deletion, ensuring the caller has authenticated.

    Args:
        index: 1-based entry index (newest-first display order).
        key: Encryption key (must decrypt the target entry).
        filename: Path to the vault file.
    """
    if filename is None:
        filename = _constants.PASSWORD_FILE
    if not filename.exists():
        print("No password history available")
        return

    with open(filename, "rb") as f:
        entries = [line.strip() for line in f if line.strip()]
    entries.reverse()

    if index < 1 or index > len(entries):
        print(f"Invalid index. Valid range: 1-{len(entries)}")
        return

    target = entries[index - 1]
    try:
        blob = base64.b64decode(target, validate=True)
        decrypt_data(blob, key)
    except Exception:
        logger.error("Cannot verify entry — wrong encryption key?")
        return

    entries.pop(index - 1)

    secure_delete_file(filename)

    entries.reverse()
    with open(filename, "wb") as f:
        f.writelines(entry + b"\n" for entry in entries)

    filename.chmod(DEFAULT_FILE_PERMISSIONS)
    print(f"[+] Entry {index} securely deleted")


def update_entry_metadata(
    index: int,
    key: bytes,
    label: str | None = None,
    category: str | None = None,
    tags: list[str] | None = None,
    filename: Path | None = None,
) -> None:
    """Update metadata fields on an existing vault entry.

    Only fields that are not ``None`` are changed; the rest keep their
    existing values.

    Args:
        index: 1-based entry index (newest-first display order).
        key: Encryption key (must decrypt the target entry).
        label: New label, or ``None`` to keep current.
        category: New category, or ``None`` to keep current.
        tags: New tag list, or ``None`` to keep current.
        filename: Path to the vault file.
    """
    if filename is None:
        filename = _constants.PASSWORD_FILE
    if not filename.exists():
        print("No password history available")
        return

    with open(filename, "rb") as f:
        entries = [line.strip() for line in f if line.strip()]
    entries.reverse()

    if index < 1 or index > len(entries):
        print(f"Invalid index. Valid range: 1-{len(entries)}")
        return

    target = entries[index - 1]
    try:
        blob = base64.b64decode(target, validate=True)
        rec_json = decrypt_data(blob, key)
    except Exception:
        logger.error("Cannot verify entry — wrong encryption key?")
        return

    rec = json.loads(rec_json)

    if label is not None:
        rec["label"] = label
    if category is not None:
        rec["category"] = category
    if tags is not None:
        rec["tags"] = tags

    updated_json = json.dumps(rec, separators=(",", ":"))
    encrypted = encrypt_data(updated_json, key)
    entries[index - 1] = base64.b64encode(encrypted)

    secure_delete_file(filename)

    entries.reverse()
    with open(filename, "wb") as f:
        f.writelines(entry + b"\n" for entry in entries)

    filename.chmod(DEFAULT_FILE_PERMISSIONS)
    print(f"[+] Entry {index} updated")
