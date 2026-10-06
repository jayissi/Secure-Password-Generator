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

from textual.widgets import Button, Input, TabbedContent

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


class TestQuitBinding:

    @pytest.mark.asyncio
    async def test_quit(self, _vault):
        app = PwgenTUI()
        async with app.run_test(size=SCREEN) as pilot:
            await pilot.press("Q")
