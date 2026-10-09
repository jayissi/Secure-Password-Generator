#!/usr/bin/env python3
"""
Textual TUI for Secure Password Generator.

Provides a graphical terminal interface with tabbed screens for
password generation, vault browsing, health reporting, and vault
configuration.  Launch with ``pwgen -t`` or ``pwgen --tui``.
"""

from __future__ import annotations

import contextlib
import io
from collections import Counter
from collections.abc import Callable
from types import SimpleNamespace
from typing import ClassVar

import segno
from textual.app import App, ComposeResult
from textual.binding import Binding, BindingType
from textual.containers import Horizontal, Vertical
from textual.message import Message
from textual.screen import ModalScreen
from textual.widgets import (
    Button,
    Checkbox,
    DataTable,
    Footer,
    Header,
    Input,
    Label,
    Static,
    TabbedContent,
    TabPane,
)

import secure_password_generator.constants as _constants
from secure_password_generator import __version__
from secure_password_generator.clipboard import (
    copy_to_clipboard,
    schedule_clipboard_clear,
)
from secure_password_generator.config import CharsetConfig
from secure_password_generator.crypto import (
    _FINAL_KEY_CACHE,
    _KEY_CACHE,
    _crypto_state,
    cleanup_files,
    get_encryption_key,
    initialize_security_files,
    is_master_password_enabled,
    resolve_master_password,
    set_master_password,
)
from secure_password_generator.generator import (
    calculate_password_strength,
    compute_charset_size,
    generate_password,
)
from secure_password_generator.history import (
    delete_entry_by_index,
    get_decrypted_entries,
    save_password,
)

# ---------------------------------------------------------------------------
# Modal dialogs
# ---------------------------------------------------------------------------


class VaultChanged(Message):
    """Posted when the vault is modified (save, delete, cleanup)."""


class MasterPasswordModal(ModalScreen[str | None]):
    """Modal dialog for master password entry."""

    BINDINGS: ClassVar[list[BindingType]] = [
        Binding("escape", "cancel", "Cancel"),
    ]

    def compose(self) -> ComposeResult:
        with Vertical(id="auth-dialog"):
            yield Label("Master Password Required", id="auth-title")
            yield Input(
                placeholder="Enter master password...",
                password=True,
                id="auth-input",
            )
            with Horizontal(id="auth-buttons"):
                yield Button("Unlock", variant="primary", id="auth-ok")
                yield Button("Cancel", id="auth-cancel")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "auth-ok":
            pw = self.query_one("#auth-input", Input).value
            self.dismiss(pw or None)
        else:
            self.dismiss(None)

    def on_input_submitted(self, _event: Input.Submitted) -> None:
        pw = self.query_one("#auth-input", Input).value
        self.dismiss(pw or None)

    def action_cancel(self) -> None:
        self.dismiss(None)


class ConfirmModal(ModalScreen[bool]):
    """Generic yes/no confirmation dialog."""

    def __init__(self, message: str) -> None:
        super().__init__()
        self._message = message

    def compose(self) -> ComposeResult:
        with Vertical(id="confirm-dialog"):
            yield Label(self._message, id="confirm-msg")
            with Horizontal(id="confirm-buttons"):
                yield Button(
                    "Yes", variant="error", id="confirm-yes",
                )
                yield Button("Cancel", id="confirm-no")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        self.dismiss(event.button.id == "confirm-yes")


class SaveModal(ModalScreen[dict | None]):
    """Modal dialog for saving password with metadata."""

    BINDINGS: ClassVar[list[BindingType]] = [
        Binding("escape", "cancel", "Cancel"),
    ]

    def compose(self) -> ComposeResult:
        with Vertical(id="save-dialog"):
            yield Label("Save Password to Vault", id="save-title")
            yield Input(placeholder="Label", id="save-label")
            yield Input(placeholder="Category", id="save-category")
            yield Input(
                placeholder="Tags (comma-sep)", id="save-tags",
            )
            with Horizontal(id="save-buttons"):
                yield Button(
                    "Save", variant="success", id="save-ok",
                )
                yield Button("Cancel", id="save-cancel")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "save-ok":
            self.dismiss({
                "label": (
                    self.query_one("#save-label", Input).value
                    or None
                ),
                "category": (
                    self.query_one("#save-category", Input).value
                    or None
                ),
                "tags": self.query_one(
                    "#save-tags", Input,
                ).value,
            })
        else:
            self.dismiss(None)

    def action_cancel(self) -> None:
        self.dismiss(None)


class QRModal(ModalScreen[None]):
    """Modal dialog displaying QR codes, sized to fit."""

    BINDINGS: ClassVar[list[BindingType]] = [
        Binding("escape", "dismiss_qr", "Close"),
    ]

    def __init__(self, qr_text: str) -> None:
        super().__init__()
        self._qr_text = qr_text
        lines = qr_text.splitlines()
        qr_width = max(
            (len(line) for line in lines), default=20,
        )
        self._dialog_width = qr_width + 8

    def compose(self) -> ComposeResult:
        dialog = Vertical(id="qr-dialog")
        dialog.styles.width = self._dialog_width
        with dialog:
            yield Static(
                self._qr_text, id="qr-content", markup=False,
            )
            yield Button("Close", id="qr-close")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        self.dismiss(None)

    def action_dismiss_qr(self) -> None:
        self.dismiss(None)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _strength_color(score: int) -> str:
    """Return a Rich colour name for the given strength score."""
    if score >= 10:
        return "bright_green"
    if score >= 8:
        return "green"
    if score >= 6:
        return "yellow"
    if score >= 4:
        return "dark_orange"
    return "red"


def _escape_markup(text: str) -> str:
    """Escape brackets for Textual/Rich markup."""
    return text.replace("[", r"\[")


# ---------------------------------------------------------------------------
# Generate pane
# ---------------------------------------------------------------------------


class GeneratePane(Static):
    """Password generation form with live output."""

    def compose(self) -> ComposeResult:
        with Vertical():
            with Horizontal(id="gen-top-row"):
                with Vertical(id="gen-length-box"):
                    yield Label("Length:")
                    yield Input(
                        value="24", id="gen-length", type="integer",
                    )
                with Vertical(id="gen-count-box"):
                    yield Label("Count:")
                    yield Input(
                        value="1", id="gen-count", type="integer",
                    )
                with Vertical(id="gen-min-box"):
                    yield Label("Min/type:")
                    yield Input(
                        value="1", id="gen-min-chars", type="integer",
                    )

            with Horizontal(id="gen-charsets"):
                yield Checkbox("Upper", value=True, id="gen-upper")
                yield Checkbox("Lower", value=True, id="gen-lower")
                yield Checkbox("Digits", value=True, id="gen-digits")
                yield Checkbox("Symbols", value=True, id="gen-symbols")

            with Horizontal(id="gen-options"):
                yield Checkbox("Blank", id="gen-blank")
                yield Checkbox("Latin-ext", id="gen-latin-ext")
                yield Checkbox("No Repeats", value=True, id="gen-no-repeats")
                yield Checkbox("Exclude Similar", id="gen-exclude-similar")

            yield Input(
                placeholder="Allowed symbols (e.g. @#$%)",
                id="gen-allowed-symbols",
            )

            with Horizontal(id="gen-actions"):
                yield Button(
                    "Generate", variant="primary", id="gen-btn",
                )
                yield Button("Copy", id="gen-copy")
                yield Button("QR", id="gen-qr")
                yield Button("Save", variant="success", id="gen-save")

            yield Static("", id="gen-output")

    def on_mount(self) -> None:
        self._passwords: list[str] = []
        self._pool_size: int | None = None

    def on_button_pressed(self, event: Button.Pressed) -> None:
        app = self.app
        if not isinstance(app, PwgenTUI):
            return

        if event.button.id == "gen-btn":
            self._do_generate()
        elif event.button.id == "gen-copy":
            self._do_copy()
        elif event.button.id == "gen-qr":
            self._do_qr()
        elif event.button.id == "gen-save":
            self._do_save()

    def _int_val(self, widget_id: str, default: int) -> int:
        try:
            return int(self.query_one(widget_id, Input).value)
        except ValueError:
            return default

    def _do_generate(self) -> None:
        length = self._int_val("#gen-length", 24)
        count = max(1, self._int_val("#gen-count", 1))
        min_chars = self._int_val("#gen-min-chars", 1)

        allowed = (
            self.query_one("#gen-allowed-symbols", Input).value or None
        )

        cfg = CharsetConfig(
            use_upper=self.query_one("#gen-upper", Checkbox).value,
            use_lower=self.query_one("#gen-lower", Checkbox).value,
            use_digits=self.query_one("#gen-digits", Checkbox).value,
            use_symbols=self.query_one(
                "#gen-symbols", Checkbox,
            ).value or bool(allowed),
            allowed_symbols=allowed,
            exclude_similar=self.query_one(
                "#gen-exclude-similar", Checkbox,
            ).value,
            blank=self.query_one("#gen-blank", Checkbox).value,
            latin_ext=self.query_one("#gen-latin-ext", Checkbox).value,
        )

        pool_size = compute_charset_size(cfg)
        no_repeats = self.query_one("#gen-no-repeats", Checkbox).value

        passwords: list[str] = []
        lines: list[str] = []
        for i in range(count):
            try:
                pw = generate_password(
                    length=length,
                    cfg=cfg,
                    min_characters_per_type=min_chars,
                    no_repeats=no_repeats,
                )
            except (ValueError, RuntimeError) as exc:
                safe_msg = _escape_markup(str(exc))
                self.query_one("#gen-output", Static).update(
                    f"[red]{safe_msg}[/red]"
                )
                return

            strength = calculate_password_strength(
                pw, charset_size=pool_size,
            )
            bar = "\u2588" * strength + "\u2591" * (10 - strength)
            color = _strength_color(strength)
            passwords.append(pw)
            safe_pw = _escape_markup(pw)
            lines.append(
                f"  {i + 1}. [bold]{safe_pw}[/bold]"
                f"  [{color}]{bar} {strength}/10[/{color}]"
            )

        self._passwords = passwords
        self._pool_size = pool_size

        self.query_one("#gen-output", Static).update(
            "\n" + "\n".join(lines) + "\n"
        )

    def _do_copy(self) -> None:
        if not self._passwords:
            self.app.notify("No password to copy", severity="warning")
            return
        text = "\n".join(self._passwords)
        if copy_to_clipboard(text):
            schedule_clipboard_clear()
            n = len(self._passwords)
            label = (
                "Copied to clipboard"
                if n == 1
                else f"Copied {n} passwords to clipboard"
            )
            self.app.notify(label)
        else:
            self.app.notify(
                "Clipboard not available", severity="error",
            )

    def _do_qr(self) -> None:
        if not self._passwords:
            self.app.notify(
                "No password generated", severity="warning",
            )
            return
        parts: list[str] = []
        for pw in self._passwords:
            qr = segno.make(pw)
            buf = io.StringIO()
            qr.terminal(out=buf, compact=True)
            parts.append(buf.getvalue())
        self.app.push_screen(QRModal("\n".join(parts)))

    def _do_save(self) -> None:
        if not self._passwords:
            self.app.notify(
                "No password to save", severity="warning",
            )
            return

        app = self.app
        if not isinstance(app, PwgenTUI):
            return

        def _on_save_modal(result: dict | None) -> None:
            if result is None:
                return

            def _save_with_key(key: bytes) -> None:
                tags_raw = result.get("tags", "")
                tags = (
                    [
                        t.strip()
                        for t in tags_raw.split(",")
                        if t.strip()
                    ]
                    if tags_raw
                    else None
                )
                for pw in self._passwords:
                    save_password(
                        pw,
                        key=key,
                        label=result.get("label"),
                        category=result.get("category"),
                        tags=tags,
                        charset_size=self._pool_size,
                    )
                n = len(self._passwords)
                pw_label = (
                    "password" if n == 1 else "passwords"
                )
                self.app.notify(
                    f"{n} {pw_label} saved to vault"
                )
                self._passwords = []
                self.query_one("#gen-output", Static).update(
                    ""
                )
                self.post_message(VaultChanged())

            app.require_key(_save_with_key)

        app.push_screen(SaveModal(), _on_save_modal)


# ---------------------------------------------------------------------------
# History pane
# ---------------------------------------------------------------------------


class HistoryPane(Static):
    """Vault browser with search and actions."""

    def compose(self) -> ComposeResult:
        with Vertical():
            yield Input(
                placeholder=(
                    "Search: label=X category=X tags=X "
                    "strength>=N or plain text"
                ),
                id="hist-search",
            )
            yield DataTable(id="hist-table")
            yield Static("", id="hist-detail")
            with Horizontal(id="hist-actions"):
                yield Button("Refresh", id="hist-refresh")
                yield Button("Reveal", id="hist-reveal")
                yield Button("Copy", id="hist-copy")
                yield Button("QR", id="hist-qr")
                yield Button(
                    "Delete", variant="error", id="hist-delete",
                )

    def on_mount(self) -> None:
        self._entries: list[dict] = []
        self._revealed = False
        table = self.query_one("#hist-table", DataTable)
        table.add_columns(
            "#", "Label", "Password", "Strength", "Category",
        )
        table.cursor_type = "row"

    @staticmethod
    def _parse_search(
        raw: str | None,
    ) -> dict[str, str | int | None]:
        """Parse structured search syntax.

        Supports:
            label=Gmail
            category=Email
            tags=work,personal
            strength>=8
            plain text  (fuzzy search across all fields)
        """
        if not raw or not raw.strip():
            return {}

        result: dict[str, str | int | None] = {}
        parts: list[str] = []

        for token in raw.strip().split():
            if "=" in token:
                key, _, val = token.partition("=")
                key_lower = key.lower().rstrip(">")
                if key_lower == "label":
                    result["search"] = val
                elif key_lower == "category":
                    result["filter_category"] = val
                elif key_lower == "tags":
                    result["search"] = val
                elif key_lower in ("strength", "strength>"):
                    with contextlib.suppress(ValueError):
                        result["filter_strength"] = int(val)
                else:
                    parts.append(token)
            else:
                parts.append(token)

        if parts and "search" not in result:
            result["search"] = " ".join(parts)

        return result

    def _load_entries(
        self, key: bytes, search: str | None = None,
    ) -> None:
        filters = self._parse_search(search)
        search_val: str | None = (
            str(filters["search"]) if "search" in filters else None
        )
        raw_strength = filters.get("filter_strength")
        strength_val: int | None = (
            int(raw_strength)
            if raw_strength is not None
            else None
        )
        category_val: str | None = (
            str(filters["filter_category"])
            if "filter_category" in filters
            else None
        )
        self._entries = get_decrypted_entries(
            key,
            search=search_val,
            filter_strength=strength_val,
            filter_category=category_val,
        )
        self._refresh_table()

    def _refresh_table(self) -> None:
        table = self.query_one("#hist-table", DataTable)
        table.clear()
        for idx, entry in enumerate(self._entries, 1):
            pw = (
                entry.get("password", "?")
                if self._revealed
                else "\u2022" * 8
            )
            strength = entry.get("strength", 0)
            table.add_row(
                str(idx),
                entry.get("label", "N/A"),
                pw,
                f"{strength}/10",
                entry.get("category", "N/A"),
            )

    def _show_empty(self) -> None:
        self.app.notify("No vault found")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        app = self.app
        if not isinstance(app, PwgenTUI):
            return

        if event.button.id == "hist-refresh":
            search = (
                self.query_one("#hist-search", Input).value or None
            )
            app.require_key_readonly(
                lambda k: self._load_entries(k, search),
                empty_callback=self._show_empty,
            )
        elif event.button.id == "hist-reveal":
            self._toggle_reveal()
        elif event.button.id == "hist-copy":
            self._do_copy()
        elif event.button.id == "hist-qr":
            self._do_qr()
        elif event.button.id == "hist-delete":
            self._do_delete()

    def on_input_submitted(self, _event: Input.Submitted) -> None:
        app = self.app
        if not isinstance(app, PwgenTUI):
            return
        search = (
            self.query_one("#hist-search", Input).value or None
        )
        app.require_key_readonly(
            lambda k: self._load_entries(k, search),
            empty_callback=self._show_empty,
        )

    def _toggle_reveal(self) -> None:
        self._revealed = not self._revealed
        btn = self.query_one("#hist-reveal", Button)
        btn.label = "Hide" if self._revealed else "Reveal"
        if self._entries:
            self._refresh_table()

    def _selected_entry(self) -> dict | None:
        table = self.query_one("#hist-table", DataTable)
        if table.cursor_row is not None and self._entries:
            idx = table.cursor_row
            if 0 <= idx < len(self._entries):
                return self._entries[idx]
        return None

    def _selected_index(self) -> int | None:
        table = self.query_one("#hist-table", DataTable)
        if table.cursor_row is not None:
            return table.cursor_row + 1
        return None

    def _do_copy(self) -> None:
        entry = self._selected_entry()
        if not entry:
            self.app.notify(
                "No entry selected", severity="warning",
            )
            return
        pw = entry.get("password", "")
        if copy_to_clipboard(pw):
            schedule_clipboard_clear()
            self.app.notify("Copied to clipboard")
        else:
            self.app.notify(
                "Clipboard not available", severity="error",
            )

    def _do_qr(self) -> None:
        entry = self._selected_entry()
        if not entry:
            self.app.notify(
                "No entry selected", severity="warning",
            )
            return
        qr = segno.make(entry.get("password", ""))
        buf = io.StringIO()
        qr.terminal(out=buf, compact=True)
        self.app.push_screen(QRModal(buf.getvalue()))

    def _do_delete(self) -> None:
        app = self.app
        if not isinstance(app, PwgenTUI):
            return
        idx = self._selected_index()
        if idx is None:
            self.app.notify(
                "No entry selected", severity="warning",
            )
            return

        captured_idx = idx

        def _on_confirm(confirmed: bool | None) -> None:
            if not confirmed:
                return

            def _delete_with_key(key: bytes) -> None:
                delete_entry_by_index(captured_idx, key)
                self.app.notify(f"Entry {captured_idx} deleted")
                self._load_entries(key)
                self.post_message(VaultChanged())

            app.require_key(_delete_with_key)

        app.push_screen(
            ConfirmModal(
                f"Delete entry {captured_idx}? This cannot be undone.",
            ),
            _on_confirm,
        )


# ---------------------------------------------------------------------------
# Status pane (formerly Health)
# ---------------------------------------------------------------------------


class StatusPane(Static):
    """Vault health / status dashboard."""

    def compose(self) -> ComposeResult:
        with Vertical():
            yield Button("Load Report", id="status-load")
            yield Static(
                "Press Load Report to analyse vault.",
                id="status-output",
            )

    def _show_empty(self) -> None:
        self.query_one("#status-output", Static).update(
            "Vault is empty -- nothing to report."
        )

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id != "status-load":
            return
        app = self.app
        if not isinstance(app, PwgenTUI):
            return
        app.require_key_readonly(
            self._build_report,
            empty_callback=self._show_empty,
        )

    def _build_report(self, key: bytes) -> None:
        entries = get_decrypted_entries(key)
        if not entries:
            self._show_empty()
            return

        scores = [e.get("strength", 0) for e in entries]
        labels = [e.get("label", "N/A") for e in entries]

        lines: list[str] = []
        lines.append(
            f"  Total passwords: [bold]{len(entries)}[/bold]\n"
        )

        dist = Counter(scores)
        lines.append("  Score distribution:")
        for score in sorted(dist, reverse=True):
            bar = "\u2588" * score + "\u2591" * (10 - score)
            color = _strength_color(score)
            lines.append(
                f"    [{color}]{bar} {score}/10[/{color}]"
                f": {dist[score]}"
            )

        weak = sum(1 for s in scores if s < 5)
        if weak:
            lines.append(
                f"\n  Warning: {weak} password(s) "
                "scored below 5/10"
            )
        else:
            lines.append(
                "\n  All passwords score 5/10 or above."
            )

        dup_labels = [
            lbl
            for lbl, cnt in Counter(labels).items()
            if cnt > 1 and lbl != "Unnamed"
        ]
        if dup_labels:
            lines.append(
                f"\n  Duplicate labels: {', '.join(dup_labels)}"
            )

        self.query_one("#status-output", Static).update(
            "\n".join(lines)
        )


# ---------------------------------------------------------------------------
# Config pane
# ---------------------------------------------------------------------------


class ConfigPane(Static):
    """Vault configuration: cleanup, master password, about."""

    def compose(self) -> ComposeResult:
        with Vertical():
            yield Label(
                f"[bold]Secure Password Generator v{__version__}[/bold]",
                id="cfg-version",
            )
            yield Static("", id="cfg-info")
            yield Button(
                "Refresh Info", id="cfg-refresh",
            )

            yield Label("")
            yield Label("[bold]Vault Cleanup[/bold]")
            yield Button(
                "Securely Delete All Vault Files",
                variant="error",
                id="cfg-cleanup",
            )

            yield Label("")
            yield Label("[bold]Master Password[/bold]")
            yield Input(
                placeholder="Current master password (if changing)",
                password=True,
                id="cfg-current-pw",
            )
            yield Input(
                placeholder="New master password",
                password=True,
                id="cfg-new-pw",
            )
            yield Input(
                placeholder="Confirm master password",
                password=True,
                id="cfg-confirm-pw",
            )
            yield Button(
                "Set Master Password",
                variant="warning",
                id="cfg-set-master",
            )

    def on_mount(self) -> None:
        self._refresh_info()

    def _refresh_info(self) -> None:
        vault_dir = _constants.PASSWORD_DIR
        vault_exists = _constants.PASSWORD_FILE.exists()
        key_exists = _constants.KEY_FILE.exists()
        master = is_master_password_enabled()
        lines = [
            f"  Vault directory: {vault_dir}",
            f"  Vault file: {'exists' if vault_exists else 'not found'}",
            f"  Encryption key: {'exists' if key_exists else 'not found'}",
            f"  Master password: {'enabled' if master else 'not set'}",
        ]
        self.query_one("#cfg-info", Static).update("\n".join(lines))

    def on_button_pressed(self, event: Button.Pressed) -> None:
        app = self.app
        if not isinstance(app, PwgenTUI):
            return

        if event.button.id == "cfg-refresh":
            self._refresh_info()
        elif event.button.id == "cfg-cleanup":
            self._do_cleanup()
        elif event.button.id == "cfg-set-master":
            self._do_set_master()

    def _do_cleanup(self) -> None:
        app = self.app
        if not isinstance(app, PwgenTUI):
            return

        def _on_confirm(confirmed: bool | None) -> None:
            if not confirmed:
                return
            cleanup_files()
            app._key = None
            _KEY_CACHE.clear()
            _FINAL_KEY_CACHE.clear()
            _crypto_state["session_id"] = None
            app.notify("Vault files securely deleted")
            self._refresh_info()
            self.post_message(VaultChanged())

        app.push_screen(
            ConfirmModal(
                "Securely delete ALL vault files? "
                "This cannot be undone.",
            ),
            _on_confirm,
        )

    def _do_set_master(self) -> None:
        new_pw = self.query_one("#cfg-new-pw", Input).value
        confirm_pw = self.query_one("#cfg-confirm-pw", Input).value

        if not new_pw:
            self.app.notify(
                "Enter a new master password", severity="warning",
            )
            return
        if new_pw != confirm_pw:
            self.app.notify(
                "Passwords do not match", severity="error",
            )
            return

        current_pw: str | None = None
        if is_master_password_enabled():
            current_pw = (
                self.query_one("#cfg-current-pw", Input).value
                or None
            )
            if not current_pw:
                self.app.notify(
                    "Enter current master password",
                    severity="warning",
                )
                return

        try:
            set_master_password(
                new_password=new_pw,
                current_password=current_pw,
            )
            self.app.notify("Master password configured")
            self.query_one("#cfg-current-pw", Input).value = ""
            self.query_one("#cfg-new-pw", Input).value = ""
            self.query_one("#cfg-confirm-pw", Input).value = ""
            self._refresh_info()
        except (ValueError, OSError) as exc:
            self.app.notify(
                f"Failed: {exc}", severity="error",
            )


# ---------------------------------------------------------------------------
# Main app
# ---------------------------------------------------------------------------


class PwgenTUI(App):
    """Textual TUI for Secure Password Generator."""

    TITLE = f"Secure Password Generator v{__version__}"
    CSS_PATH = "tui.tcss"
    BINDINGS: ClassVar[list[BindingType]] = [
        Binding("g", "switch_tab('generate')", "Generate"),
        Binding("h", "switch_tab('history')", "History"),
        Binding("s", "switch_tab('status')", "Status"),
        Binding("c", "switch_tab('config')", "Config"),
        Binding("Q", "quit", "Quit", key_display="Q"),
    ]

    def __init__(self) -> None:
        super().__init__()
        self._key: bytes | None = None

    def compose(self) -> ComposeResult:
        yield Header()
        with TabbedContent(id="tabs"):
            with TabPane("Generate", id="tab-generate"):
                yield GeneratePane()
            with TabPane("History", id="tab-history"):
                yield HistoryPane()
            with TabPane("Status", id="tab-status"):
                yield StatusPane()
            with TabPane("Config", id="tab-config"):
                yield ConfigPane()
        yield Footer()

    def on_mount(self) -> None:
        """Prompt for master password on startup if enabled."""
        if is_master_password_enabled():
            self.push_screen(
                MasterPasswordModal(),
                self._on_startup_auth,
            )

    def _on_startup_auth(self, pw: str | None) -> None:
        if pw is None:
            self.exit()
            return
        try:
            self._key = get_encryption_key(pw)
        except (ValueError, OSError):
            self.notify(
                "Wrong password", severity="error",
            )
            self.exit()

    def on_vault_changed(self, _event: VaultChanged) -> None:
        """Auto-refresh History and Status when vault changes."""
        self._refresh_history_status()

    def _refresh_history_status(self) -> None:
        """Reload History and Status panes from vault."""
        try:
            hist = self.query_one(HistoryPane)
            if self._key and _constants.PASSWORD_FILE.exists():
                hist._load_entries(self._key)
            else:
                hist._entries = []
                hist._refresh_table()
        except (ValueError, OSError):
            pass
        try:
            status = self.query_one(StatusPane)
            if self._key and _constants.PASSWORD_FILE.exists():
                status._build_report(self._key)
            else:
                status.query_one(
                    "#status-output", Static,
                ).update("No vault found.")
        except (ValueError, OSError):
            pass

    def action_switch_tab(self, tab_id: str) -> None:
        tabs = self.query_one("#tabs", TabbedContent)
        tabs.active = f"tab-{tab_id}"
        tabs.focus()
        if tab_id in ("history", "status"):
            self._refresh_history_status()

    def on_tabbed_content_tab_activated(
        self, event: TabbedContent.TabActivated,
    ) -> None:
        """Refresh History/Status when tab is clicked."""
        tab_id = event.pane.id or ""
        if tab_id in ("tab-history", "tab-status"):
            self._refresh_history_status()

    def require_key(
        self, callback: Callable[[bytes], None],
    ) -> None:
        """Resolve the encryption key (creates files if needed)."""
        if self._key is not None:
            callback(self._key)
            return

        initialize_security_files()

        if is_master_password_enabled():
            def _on_password(pw: str | None) -> None:
                if pw is None:
                    self.notify(
                        "Authentication cancelled",
                        severity="warning",
                    )
                    return
                try:
                    self._key = get_encryption_key(pw)
                    callback(self._key)
                except (ValueError, OSError) as exc:
                    self.notify(
                        f"Auth failed: {exc}",
                        severity="error",
                    )

            self.push_screen(
                MasterPasswordModal(), _on_password,
            )
        else:
            try:
                args = SimpleNamespace(
                    master_password=None,
                    master_password_file=None,
                )
                master_pw = resolve_master_password(args)
                self._key = get_encryption_key(master_pw)
                callback(self._key)
            except (ValueError, OSError) as exc:
                self.notify(
                    f"Key error: {exc}", severity="error",
                )

    def require_key_readonly(
        self,
        callback: Callable[[bytes], None],
        empty_callback: Callable[[], None] | None = None,
    ) -> None:
        """Resolve key only if vault exists (no file creation)."""
        if self._key is not None:
            callback(self._key)
            return

        if not _constants.PASSWORD_FILE.exists():
            if empty_callback:
                empty_callback()
            else:
                self.notify("No vault found", severity="warning")
            return

        self.require_key(callback)

    async def action_quit(self) -> None:
        """Quit the TUI and clear cached keys."""
        self._cleanup()
        self.exit()

    def on_unmount(self) -> None:
        self._cleanup()

    def _cleanup(self) -> None:
        """Clear cached crypto state."""
        self._key = None
        _KEY_CACHE.clear()
        _FINAL_KEY_CACHE.clear()
        _crypto_state["session_id"] = None
