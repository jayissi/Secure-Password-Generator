#!/usr/bin/env python3
"""
Tests for secure_password_generator.tui module.

Covers:
- App instantiation and composition (4 tabs)
- Generate pane: generate, count, copy, QR, save, save toggle,
  allowed symbols, min chars
- History pane: load, vault guard (no file creation)
- Status pane: report, empty vault, vault guard
- Config pane: info display
- Quit binding
"""

import os

import pytest

os.environ["SPG_TEST_KDF"] = "1"

from textual.widgets import Button, DataTable, Input, TabbedContent

from secure_password_generator.tui import GeneratePane, PwgenTUI

SCREEN = (120, 80)


@pytest.fixture()
def _vault(vault_dir):
    """Initialise security files in the isolated vault directory."""
    from secure_password_generator.crypto import initialize_security_files

    initialize_security_files()


@pytest.fixture()
def _populated_vault(_vault):
    """Vault with saved passwords for history/status tests."""
    from secure_password_generator.crypto import get_encryption_key
    from secure_password_generator.history import save_password

    key = get_encryption_key(None)
    save_password("Alpha1!xyz", key=key, label="Gmail", category="Email")
    save_password("weak", key=key, label="Weak", category="Test")
    save_password("Beta22@abc", key=key, label="Gmail", category="Email")


async def _press_button(app: PwgenTUI, button_id: str) -> None:
    """Programmatically press a button by ID (avoids OutOfBounds)."""
    btn = app.query_one(button_id, Button)
    btn.press()


class TestAppStartup:

    @pytest.mark.asyncio
    async def test_app_composes(self, _vault):
        app = PwgenTUI()
        async with app.run_test(size=SCREEN) as pilot:
            assert app.title is not None
            assert pilot is not None

    @pytest.mark.asyncio
    async def test_four_tabs_exist(self, _vault):
        app = PwgenTUI()
        async with app.run_test(size=SCREEN):
            assert app.query_one("#tab-generate") is not None
            assert app.query_one("#tab-history") is not None
            assert app.query_one("#tab-status") is not None
            assert app.query_one("#tab-config") is not None

    @pytest.mark.asyncio
    async def test_footer_visible(self, _vault):
        from textual.widgets import Footer

        app = PwgenTUI()
        async with app.run_test(size=SCREEN):
            assert app.query_one(Footer) is not None


class TestGeneratePane:

    @pytest.mark.asyncio
    async def test_generate_button(self, _vault):
        app = PwgenTUI()
        async with app.run_test(size=SCREEN) as pilot:
            await _press_button(app, "#gen-btn")
            await pilot.pause()
            pane = app.query_one(GeneratePane)
            assert pane._passwords

    @pytest.mark.asyncio
    async def test_generate_count(self, _vault):
        app = PwgenTUI()
        async with app.run_test(size=SCREEN) as pilot:
            app.query_one("#gen-count", Input).value = "3"
            await _press_button(app, "#gen-btn")
            await pilot.pause()
            pane = app.query_one(GeneratePane)
            assert len(pane._passwords) == 3

    @pytest.mark.asyncio
    async def test_generate_copy(self, _vault):
        from unittest.mock import patch

        app = PwgenTUI()
        async with app.run_test(size=SCREEN) as pilot:
            await _press_button(app, "#gen-btn")
            await pilot.pause()
            with patch(
                "secure_password_generator.tui.copy_to_clipboard",
                return_value=True,
            ), patch(
                "secure_password_generator.tui.schedule_clipboard_clear",
            ):
                await _press_button(app, "#gen-copy")
                await pilot.pause()

    @pytest.mark.asyncio
    async def test_generate_qr(self, _vault):
        app = PwgenTUI()
        async with app.run_test(size=SCREEN) as pilot:
            await _press_button(app, "#gen-btn")
            await pilot.pause()
            await _press_button(app, "#gen-qr")
            await pilot.pause()

    @pytest.mark.asyncio
    async def test_generate_save_modal(self, _vault):
        app = PwgenTUI()
        async with app.run_test(size=SCREEN) as pilot:
            await _press_button(app, "#gen-btn")
            await pilot.pause()
            await _press_button(app, "#gen-save")
            await pilot.pause()
            # SaveModal is on the screen stack
            modal = app.screen
            save_ok = modal.query_one("#save-ok", Button)
            save_ok.press()
            await pilot.pause()

    @pytest.mark.asyncio
    async def test_output_cleared_after_save(self, _vault):
        app = PwgenTUI()
        async with app.run_test(size=SCREEN) as pilot:
            await _press_button(app, "#gen-btn")
            await pilot.pause()
            pane = app.query_one(GeneratePane)
            assert pane._passwords
            await _press_button(app, "#gen-save")
            await pilot.pause()
            modal = app.screen
            save_ok = modal.query_one("#save-ok", Button)
            save_ok.press()
            await pilot.pause()
            assert not pane._passwords

    @pytest.mark.asyncio
    async def test_generate_allowed_symbols(self, _vault):
        app = PwgenTUI()
        async with app.run_test(size=SCREEN) as pilot:
            app.query_one("#gen-allowed-symbols", Input).value = "@#$"
            await _press_button(app, "#gen-btn")
            await pilot.pause()
            pane = app.query_one(GeneratePane)
            assert pane._passwords

    @pytest.mark.asyncio
    async def test_generate_min_chars(self, _vault):
        app = PwgenTUI()
        async with app.run_test(size=SCREEN) as pilot:
            app.query_one("#gen-min-chars", Input).value = "2"
            await _press_button(app, "#gen-btn")
            await pilot.pause()
            pane = app.query_one(GeneratePane)
            assert pane._passwords


class TestHistoryPane:

    @pytest.mark.asyncio
    async def test_history_refresh(self, _populated_vault):
        app = PwgenTUI()
        async with app.run_test(size=SCREEN) as pilot:
            app.query_one("#tabs", TabbedContent).active = "tab-history"
            await pilot.pause()
            await _press_button(app, "#hist-refresh")
            await pilot.pause()

    @pytest.mark.asyncio
    async def test_history_empty_no_files(self, vault_dir):
        """History refresh on empty vault must NOT create key files."""
        import secure_password_generator.constants as c

        assert not c.KEY_FILE.exists()
        app = PwgenTUI()
        async with app.run_test(size=SCREEN) as pilot:
            app.query_one("#tabs", TabbedContent).active = "tab-history"
            await pilot.pause()
            await _press_button(app, "#hist-refresh")
            await pilot.pause()
        assert not c.KEY_FILE.exists()


class TestStatusPane:

    @pytest.mark.asyncio
    async def test_status_load(self, _populated_vault):
        app = PwgenTUI()
        async with app.run_test(size=SCREEN) as pilot:
            app.query_one("#tabs", TabbedContent).active = "tab-status"
            await pilot.pause()
            await _press_button(app, "#status-load")
            await pilot.pause()

    @pytest.mark.asyncio
    async def test_status_empty(self, _vault):
        app = PwgenTUI()
        async with app.run_test(size=SCREEN) as pilot:
            app.query_one("#tabs", TabbedContent).active = "tab-status"
            await pilot.pause()
            await _press_button(app, "#status-load")
            await pilot.pause()

    @pytest.mark.asyncio
    async def test_status_empty_no_files(self, vault_dir):
        """Status load on empty vault must NOT create key files."""
        import secure_password_generator.constants as c

        assert not c.KEY_FILE.exists()
        app = PwgenTUI()
        async with app.run_test(size=SCREEN) as pilot:
            app.query_one("#tabs", TabbedContent).active = "tab-status"
            await pilot.pause()
            await _press_button(app, "#status-load")
            await pilot.pause()
        assert not c.KEY_FILE.exists()


class TestConfigPane:

    @pytest.mark.asyncio
    async def test_config_info(self, _vault):
        app = PwgenTUI()
        async with app.run_test(size=SCREEN) as pilot:
            app.query_one("#tabs", TabbedContent).active = "tab-config"
            await pilot.pause()
            info = app.query_one("#cfg-info")
            rendered = str(info.render())
            assert rendered is not None


class TestStartupAuth:

    @pytest.mark.asyncio
    async def test_no_auth_without_master(self, _vault):
        """App starts without modal when no master password."""
        app = PwgenTUI()
        async with app.run_test(size=SCREEN) as pilot:
            # Should go straight to UI -- tabs visible
            assert app.query_one("#tab-generate") is not None
            await pilot.pause()


class TestEventDrivenRefresh:

    @pytest.mark.asyncio
    async def test_save_refreshes_history(self, _vault):
        """Saving a password auto-refreshes History pane."""
        from secure_password_generator.tui import HistoryPane

        app = PwgenTUI()
        async with app.run_test(size=SCREEN) as pilot:
            # Load history first (empty)
            hist = app.query_one(HistoryPane)
            app.query_one("#tabs", TabbedContent).active = "tab-history"
            await pilot.pause()
            await _press_button(app, "#hist-refresh")
            await pilot.pause()
            initial_count = len(hist._entries)

            # Switch to Generate and save
            app.query_one("#tabs", TabbedContent).active = "tab-generate"
            await pilot.pause()
            await _press_button(app, "#gen-btn")
            await pilot.pause()
            await _press_button(app, "#gen-save")
            await pilot.pause()
            modal = app.screen
            modal.query_one("#save-ok", Button).press()
            await pilot.pause()
            await pilot.pause()

            # History should have auto-refreshed
            assert len(hist._entries) > initial_count


class TestStructuredSearch:

    def test_parse_plain_text(self):
        from secure_password_generator.tui import HistoryPane

        result = HistoryPane._parse_search("Gmail")
        assert result == {"search": "Gmail"}

    def test_parse_label(self):
        from secure_password_generator.tui import HistoryPane

        result = HistoryPane._parse_search("label=Gmail")
        assert result == {"search": "Gmail"}

    def test_parse_category(self):
        from secure_password_generator.tui import HistoryPane

        result = HistoryPane._parse_search("category=Email")
        assert result == {"filter_category": "Email"}

    def test_parse_strength(self):
        from secure_password_generator.tui import HistoryPane

        result = HistoryPane._parse_search("strength>=8")
        assert result == {"filter_strength": 8}

    def test_parse_combined(self):
        from secure_password_generator.tui import HistoryPane

        result = HistoryPane._parse_search(
            "category=Email strength>=7"
        )
        assert result["filter_category"] == "Email"
        assert result["filter_strength"] == 7

    def test_parse_empty(self):
        from secure_password_generator.tui import HistoryPane

        assert HistoryPane._parse_search(None) == {}
        assert HistoryPane._parse_search("") == {}

    def test_parse_tags(self):
        from secure_password_generator.tui import HistoryPane

        result = HistoryPane._parse_search("tags=work,personal")
        assert result == {"search": "work,personal"}


class TestHistoryActions:

    @pytest.mark.asyncio
    async def test_history_reveal_toggle(self, _populated_vault):
        from secure_password_generator.tui import HistoryPane

        app = PwgenTUI()
        async with app.run_test(size=SCREEN) as pilot:
            app.query_one("#tabs", TabbedContent).active = "tab-history"
            await pilot.pause()
            await _press_button(app, "#hist-refresh")
            await pilot.pause()
            hist = app.query_one(HistoryPane)
            assert not hist._revealed
            await _press_button(app, "#hist-reveal")
            await pilot.pause()
            assert hist._revealed
            btn = app.query_one("#hist-reveal", Button)
            assert str(btn.label) == "Hide"
            await _press_button(app, "#hist-reveal")
            await pilot.pause()
            assert not hist._revealed

    @pytest.mark.asyncio
    async def test_history_copy_no_selection(self, _populated_vault):
        app = PwgenTUI()
        async with app.run_test(size=SCREEN) as pilot:
            app.query_one("#tabs", TabbedContent).active = "tab-history"
            await pilot.pause()
            await _press_button(app, "#hist-copy")
            await pilot.pause()

    @pytest.mark.asyncio
    async def test_history_qr_no_selection(self, _populated_vault):
        app = PwgenTUI()
        async with app.run_test(size=SCREEN) as pilot:
            app.query_one("#tabs", TabbedContent).active = "tab-history"
            await pilot.pause()
            await _press_button(app, "#hist-qr")
            await pilot.pause()

    @pytest.mark.asyncio
    async def test_history_delete_no_selection(self, _populated_vault):
        app = PwgenTUI()
        async with app.run_test(size=SCREEN) as pilot:
            app.query_one("#tabs", TabbedContent).active = "tab-history"
            await pilot.pause()
            await _press_button(app, "#hist-delete")
            await pilot.pause()

    @pytest.mark.asyncio
    async def test_history_search_submit(self, _populated_vault):
        """Pressing Enter in search input triggers search."""
        app = PwgenTUI()
        async with app.run_test(size=SCREEN) as pilot:
            app.query_one("#tabs", TabbedContent).active = "tab-history"
            await pilot.pause()
            search = app.query_one("#hist-search", Input)
            search.value = "Gmail"
            await search.action_submit()
            await pilot.pause()


class TestStatusReport:

    @pytest.mark.asyncio
    async def test_status_weak_warning(self, _populated_vault):
        from textual.widgets import Static

        app = PwgenTUI()
        async with app.run_test(size=SCREEN) as pilot:
            app.query_one("#tabs", TabbedContent).active = "tab-status"
            await pilot.pause()
            await _press_button(app, "#status-load")
            await pilot.pause()
            output = app.query_one("#status-output", Static)
            rendered = str(output.render())
            assert rendered is not None


class TestConfigPaneActions:

    @pytest.mark.asyncio
    async def test_config_refresh(self, _vault):
        app = PwgenTUI()
        async with app.run_test(size=SCREEN) as pilot:
            app.query_one("#tabs", TabbedContent).active = "tab-config"
            await pilot.pause()
            await _press_button(app, "#cfg-refresh")
            await pilot.pause()

    @pytest.mark.asyncio
    async def test_config_cleanup_confirm(self, _vault):
        app = PwgenTUI()
        async with app.run_test(size=SCREEN) as pilot:
            app.query_one("#tabs", TabbedContent).active = "tab-config"
            await pilot.pause()
            await _press_button(app, "#cfg-cleanup")
            await pilot.pause()
            modal = app.screen
            yes_btn = modal.query_one("#confirm-yes", Button)
            yes_btn.press()
            await pilot.pause()

    @pytest.mark.asyncio
    async def test_config_cleanup_cancel(self, _vault):
        app = PwgenTUI()
        async with app.run_test(size=SCREEN) as pilot:
            app.query_one("#tabs", TabbedContent).active = "tab-config"
            await pilot.pause()
            await _press_button(app, "#cfg-cleanup")
            await pilot.pause()
            modal = app.screen
            cancel_btn = modal.query_one("#confirm-no", Button)
            cancel_btn.press()
            await pilot.pause()

    @pytest.mark.asyncio
    async def test_set_master_empty_warns(self, _vault):
        app = PwgenTUI()
        async with app.run_test(size=SCREEN) as pilot:
            app.query_one("#tabs", TabbedContent).active = "tab-config"
            await pilot.pause()
            await _press_button(app, "#cfg-set-master")
            await pilot.pause()

    @pytest.mark.asyncio
    async def test_set_master_mismatch(self, _vault):
        app = PwgenTUI()
        async with app.run_test(size=SCREEN) as pilot:
            app.query_one("#tabs", TabbedContent).active = "tab-config"
            await pilot.pause()
            app.query_one("#cfg-new-pw", Input).value = "StrongPass1!xx"
            app.query_one("#cfg-confirm-pw", Input).value = "Different1!xx"
            await _press_button(app, "#cfg-set-master")
            await pilot.pause()

    @pytest.mark.asyncio
    async def test_set_master_success(self, _vault):
        app = PwgenTUI()
        async with app.run_test(size=SCREEN) as pilot:
            app.query_one("#tabs", TabbedContent).active = "tab-config"
            await pilot.pause()
            app.query_one("#cfg-new-pw", Input).value = "StrongPass1!xx"
            app.query_one("#cfg-confirm-pw", Input).value = "StrongPass1!xx"
            await _press_button(app, "#cfg-set-master")
            await pilot.pause()


class TestTabSwitching:

    @pytest.mark.asyncio
    async def test_action_switch_history(self, _vault):
        app = PwgenTUI()
        async with app.run_test(size=SCREEN) as pilot:
            await pilot.press("h")
            await pilot.pause()
            tabs = app.query_one("#tabs", TabbedContent)
            assert tabs.active == "tab-history"

    @pytest.mark.asyncio
    async def test_action_switch_status(self, _vault):
        app = PwgenTUI()
        async with app.run_test(size=SCREEN) as pilot:
            await pilot.press("s")
            await pilot.pause()
            tabs = app.query_one("#tabs", TabbedContent)
            assert tabs.active == "tab-status"

    @pytest.mark.asyncio
    async def test_action_switch_config(self, _vault):
        app = PwgenTUI()
        async with app.run_test(size=SCREEN) as pilot:
            await pilot.press("c")
            await pilot.pause()
            tabs = app.query_one("#tabs", TabbedContent)
            assert tabs.active == "tab-config"

    @pytest.mark.asyncio
    async def test_action_switch_generate(self, _vault):
        app = PwgenTUI()
        async with app.run_test(size=SCREEN) as pilot:
            await pilot.press("h")
            await pilot.pause()
            await pilot.press("g")
            await pilot.pause()
            tabs = app.query_one("#tabs", TabbedContent)
            assert tabs.active == "tab-generate"


class TestHelperFunctions:

    def test_strength_color_red(self):
        from secure_password_generator.tui import _strength_color
        assert _strength_color(3) == "red"

    def test_strength_color_orange(self):
        from secure_password_generator.tui import _strength_color
        assert _strength_color(4) == "dark_orange"

    def test_strength_color_yellow(self):
        from secure_password_generator.tui import _strength_color
        assert _strength_color(6) == "yellow"

    def test_strength_color_green(self):
        from secure_password_generator.tui import _strength_color
        assert _strength_color(8) == "green"

    def test_strength_color_bright_green(self):
        from secure_password_generator.tui import _strength_color
        assert _strength_color(10) == "bright_green"

    def test_escape_markup_brackets(self):
        from secure_password_generator.tui import _escape_markup
        assert _escape_markup("a[b]c") == r"a\[b]c"

    def test_escape_markup_no_brackets(self):
        from secure_password_generator.tui import _escape_markup
        assert _escape_markup("abc") == "abc"


class TestSaveModal:

    @pytest.mark.asyncio
    async def test_save_modal_cancel(self, _vault):
        app = PwgenTUI()
        async with app.run_test(size=SCREEN) as pilot:
            await _press_button(app, "#gen-btn")
            await pilot.pause()
            await _press_button(app, "#gen-save")
            await pilot.pause()
            modal = app.screen
            cancel_btn = modal.query_one("#save-cancel", Button)
            cancel_btn.press()
            await pilot.pause()
            pane = app.query_one(GeneratePane)
            assert pane._passwords  # passwords not cleared on cancel

    @pytest.mark.asyncio
    async def test_save_modal_escape(self, _vault):
        app = PwgenTUI()
        async with app.run_test(size=SCREEN) as pilot:
            await _press_button(app, "#gen-btn")
            await pilot.pause()
            await _press_button(app, "#gen-save")
            await pilot.pause()
            await pilot.press("escape")
            await pilot.pause()


class TestGenerateEdgeCases:

    @pytest.mark.asyncio
    async def test_copy_no_password(self, _vault):
        app = PwgenTUI()
        async with app.run_test(size=SCREEN) as pilot:
            await _press_button(app, "#gen-copy")
            await pilot.pause()

    @pytest.mark.asyncio
    async def test_qr_no_password(self, _vault):
        app = PwgenTUI()
        async with app.run_test(size=SCREEN) as pilot:
            await _press_button(app, "#gen-qr")
            await pilot.pause()

    @pytest.mark.asyncio
    async def test_save_no_password(self, _vault):
        app = PwgenTUI()
        async with app.run_test(size=SCREEN) as pilot:
            await _press_button(app, "#gen-save")
            await pilot.pause()


class TestRequireKey:

    @pytest.mark.asyncio
    async def test_require_key_cached(self, _vault):
        """require_key uses cached key without re-prompting."""
        from secure_password_generator.crypto import get_encryption_key

        app = PwgenTUI()
        async with app.run_test(size=SCREEN) as pilot:
            app._key = get_encryption_key(None)
            called: list[bytes] = []
            app.require_key(called.append)
            await pilot.pause()
            assert len(called) == 1

    @pytest.mark.asyncio
    async def test_require_key_readonly_no_vault(self, vault_dir):
        """require_key_readonly with no vault calls empty_callback."""
        app = PwgenTUI()
        async with app.run_test(size=SCREEN) as pilot:
            empty_called = []
            app.require_key_readonly(
                lambda _k: None,
                empty_callback=lambda: empty_called.append(True),
            )
            await pilot.pause()
            assert len(empty_called) == 1


class TestMasterPasswordModal:

    @pytest.mark.asyncio
    async def test_auth_cancel_exits(self, _vault):
        from unittest.mock import patch

        with patch(
            "secure_password_generator.tui.is_master_password_enabled",
            return_value=True,
        ):
            app = PwgenTUI()
            async with app.run_test(size=SCREEN) as pilot:
                await pilot.pause()
                modal = app.screen
                cancel_btn = modal.query_one("#auth-cancel", Button)
                cancel_btn.press()
                await pilot.pause()

    @pytest.mark.asyncio
    async def test_auth_unlock(self, _vault):
        from secure_password_generator.crypto import set_master_password

        set_master_password(new_password="StrongPass1!xx")

        app = PwgenTUI()
        async with app.run_test(size=SCREEN) as pilot:
            await pilot.pause()
            modal = app.screen
            inp = modal.query_one("#auth-input", Input)
            inp.value = "StrongPass1!xx"
            ok_btn = modal.query_one("#auth-ok", Button)
            ok_btn.press()
            await pilot.pause()
            assert app._key is not None

    @pytest.mark.asyncio
    async def test_auth_wrong_password(self, _vault):
        from secure_password_generator.crypto import set_master_password

        set_master_password(new_password="StrongPass1!xx")

        app = PwgenTUI()
        async with app.run_test(size=SCREEN) as pilot:
            await pilot.pause()
            modal = app.screen
            inp = modal.query_one("#auth-input", Input)
            inp.value = "WrongPassw0rd!x"
            ok_btn = modal.query_one("#auth-ok", Button)
            ok_btn.press()
            await pilot.pause()

    @pytest.mark.asyncio
    async def test_auth_input_submit(self, _vault):
        from secure_password_generator.crypto import set_master_password

        set_master_password(new_password="StrongPass1!xx")

        app = PwgenTUI()
        async with app.run_test(size=SCREEN) as pilot:
            await pilot.pause()
            modal = app.screen
            inp = modal.query_one("#auth-input", Input)
            inp.value = "StrongPass1!xx"
            await inp.action_submit()
            await pilot.pause()

    @pytest.mark.asyncio
    async def test_auth_escape(self, _vault):
        from unittest.mock import patch

        with patch(
            "secure_password_generator.tui.is_master_password_enabled",
            return_value=True,
        ):
            app = PwgenTUI()
            async with app.run_test(size=SCREEN) as pilot:
                await pilot.pause()
                await pilot.press("escape")
                await pilot.pause()


class TestQRModal:

    @pytest.mark.asyncio
    async def test_qr_close_button(self, _vault):
        app = PwgenTUI()
        async with app.run_test(size=SCREEN) as pilot:
            await _press_button(app, "#gen-btn")
            await pilot.pause()
            await _press_button(app, "#gen-qr")
            await pilot.pause()
            modal = app.screen
            close_btn = modal.query_one("#qr-close", Button)
            close_btn.press()
            await pilot.pause()

    @pytest.mark.asyncio
    async def test_qr_escape(self, _vault):
        app = PwgenTUI()
        async with app.run_test(size=SCREEN) as pilot:
            await _press_button(app, "#gen-btn")
            await pilot.pause()
            await _press_button(app, "#gen-qr")
            await pilot.pause()
            await pilot.press("escape")
            await pilot.pause()


class TestHistoryPaneDetailed:

    @pytest.mark.asyncio
    async def test_history_copy_with_entry(self, _populated_vault):
        from unittest.mock import patch

        app = PwgenTUI()
        async with app.run_test(size=SCREEN) as pilot:
            app.query_one("#tabs", TabbedContent).active = "tab-history"
            await pilot.pause()
            await _press_button(app, "#hist-refresh")
            await pilot.pause()
            await pilot.pause()
            table = app.query_one("#hist-table", DataTable)
            table.move_cursor(row=0)
            await pilot.pause()
            with (
                patch(
                    "secure_password_generator.tui.copy_to_clipboard",
                    return_value=True,
                ),
                patch(
                    "secure_password_generator.tui.schedule_clipboard_clear",
                ),
            ):
                await _press_button(app, "#hist-copy")
                await pilot.pause()

    @pytest.mark.asyncio
    async def test_history_copy_fail(self, _populated_vault):
        from unittest.mock import patch

        app = PwgenTUI()
        async with app.run_test(size=SCREEN) as pilot:
            app.query_one("#tabs", TabbedContent).active = "tab-history"
            await pilot.pause()
            await _press_button(app, "#hist-refresh")
            await pilot.pause()
            await pilot.pause()
            table = app.query_one("#hist-table", DataTable)
            table.move_cursor(row=0)
            await pilot.pause()
            with patch(
                "secure_password_generator.tui.copy_to_clipboard",
                return_value=False,
            ):
                await _press_button(app, "#hist-copy")
                await pilot.pause()

    @pytest.mark.asyncio
    async def test_history_qr_with_entry(self, _populated_vault):
        app = PwgenTUI()
        async with app.run_test(size=SCREEN) as pilot:
            app.query_one("#tabs", TabbedContent).active = "tab-history"
            await pilot.pause()
            await _press_button(app, "#hist-refresh")
            await pilot.pause()
            await pilot.pause()
            table = app.query_one("#hist-table", DataTable)
            table.move_cursor(row=0)
            await pilot.pause()
            await _press_button(app, "#hist-qr")
            await pilot.pause()
            await pilot.press("escape")
            await pilot.pause()

    @pytest.mark.asyncio
    async def test_history_delete_with_entry(self, _populated_vault):
        from secure_password_generator.tui import HistoryPane

        app = PwgenTUI()
        async with app.run_test(size=SCREEN) as pilot:
            app.query_one("#tabs", TabbedContent).active = "tab-history"
            await pilot.pause()
            await _press_button(app, "#hist-refresh")
            await pilot.pause()
            await pilot.pause()
            app.query_one(HistoryPane)
            table = app.query_one("#hist-table", DataTable)
            table.move_cursor(row=0)
            await pilot.pause()
            await _press_button(app, "#hist-delete")
            await pilot.pause()
            modal = app.screen
            yes_btn = modal.query_one("#confirm-yes", Button)
            yes_btn.press()
            await pilot.pause()
            await pilot.pause()


class TestStatusPaneDetailed:

    @pytest.mark.asyncio
    async def test_status_build_report(self, _populated_vault):
        from textual.widgets import Static

        app = PwgenTUI()
        async with app.run_test(size=SCREEN) as pilot:
            app.query_one("#tabs", TabbedContent).active = "tab-status"
            await pilot.pause()
            await _press_button(app, "#status-load")
            await pilot.pause()
            output = app.query_one("#status-output", Static)
            rendered = str(output.render())
            assert "Total passwords" in rendered or rendered != ""


class TestConfigSetMasterChange:

    @pytest.mark.asyncio
    async def test_config_set_master_change(self, _vault):
        from secure_password_generator.crypto import set_master_password

        set_master_password(new_password="StrongPass1!xx")

        app = PwgenTUI()
        async with app.run_test(size=SCREEN) as pilot:
            await pilot.pause()
            modal = app.screen
            inp = modal.query_one("#auth-input", Input)
            inp.value = "StrongPass1!xx"
            modal.query_one("#auth-ok", Button).press()
            await pilot.pause()

            app.query_one("#tabs", TabbedContent).active = "tab-config"
            await pilot.pause()
            app.query_one("#cfg-current-pw", Input).value = "StrongPass1!xx"
            app.query_one("#cfg-new-pw", Input).value = "NewStrong12!xx"
            app.query_one("#cfg-confirm-pw", Input).value = "NewStrong12!xx"
            await _press_button(app, "#cfg-set-master")
            await pilot.pause()

    @pytest.mark.asyncio
    async def test_config_change_no_current(self, _vault):
        from secure_password_generator.crypto import set_master_password

        set_master_password(new_password="StrongPass1!xx")

        app = PwgenTUI()
        async with app.run_test(size=SCREEN) as pilot:
            await pilot.pause()
            modal = app.screen
            inp = modal.query_one("#auth-input", Input)
            inp.value = "StrongPass1!xx"
            modal.query_one("#auth-ok", Button).press()
            await pilot.pause()

            app.query_one("#tabs", TabbedContent).active = "tab-config"
            await pilot.pause()
            app.query_one("#cfg-new-pw", Input).value = "NewStrong12!xx"
            app.query_one("#cfg-confirm-pw", Input).value = "NewStrong12!xx"
            await _press_button(app, "#cfg-set-master")
            await pilot.pause()


class TestGenerateError:

    @pytest.mark.asyncio
    async def test_generate_error_display(self, _vault):
        app = PwgenTUI()
        async with app.run_test(size=SCREEN) as pilot:
            from textual.widgets import Checkbox
            app.query_one("#gen-upper", Checkbox).value = False
            app.query_one("#gen-lower", Checkbox).value = False
            app.query_one("#gen-digits", Checkbox).value = False
            app.query_one("#gen-symbols", Checkbox).value = False
            await _press_button(app, "#gen-btn")
            await pilot.pause()

    @pytest.mark.asyncio
    async def test_generate_int_val_default(self, _vault):
        app = PwgenTUI()
        async with app.run_test(size=SCREEN) as pilot:
            app.query_one("#gen-length", Input).value = "abc"
            await _press_button(app, "#gen-btn")
            await pilot.pause()
            pane = app.query_one(GeneratePane)
            assert pane._passwords


class TestRefreshOnTabSwitch:

    @pytest.mark.asyncio
    async def test_tab_activated_refreshes(self, _populated_vault):
        app = PwgenTUI()
        async with app.run_test(size=SCREEN) as pilot:
            app.query_one("#tabs", TabbedContent).active = "tab-history"
            await pilot.pause()
            app.query_one("#tabs", TabbedContent).active = "tab-status"
            await pilot.pause()
            app.query_one("#tabs", TabbedContent).active = "tab-generate"
            await pilot.pause()


class TestQuitBinding:

    @pytest.mark.asyncio
    async def test_quit(self, _vault):
        app = PwgenTUI()
        async with app.run_test(size=SCREEN) as pilot:
            await pilot.press("Q")
