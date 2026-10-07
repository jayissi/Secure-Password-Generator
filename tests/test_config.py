#!/usr/bin/env python3

"""
Tests for secure_password_generator.config module.

Covers:
- load_config raises ConfigError (not sys.exit)
- YAML and JSON parsing
- Unknown key rejection
- blank_space key mapping
- CharsetConfig immutability
"""

import json

import pytest
import yaml

from secure_password_generator.config import (
    CharsetConfig,
    ConfigError,
    load_config,
)

# ── load_config ──────────────────────────────────────────────────────────

class TestLoadConfig:

    def test_missing_file_raises_config_error(self, tmp_path):
        with pytest.raises(ConfigError, match="not found"):
            load_config(str(tmp_path / "nonexistent.yaml"))

    def test_yaml_round_trip(self, tmp_path):
        cfg_path = tmp_path / "test.yaml"
        cfg_path.write_text(
            yaml.dump({"length": 24, "upper": True, "lower": True})
        )
        result = load_config(str(cfg_path))
        assert result["length"] == 24
        assert result["upper"] is True

    def test_json_round_trip(self, tmp_path):
        cfg_path = tmp_path / "test.json"
        cfg_path.write_text(
            json.dumps({"length": 18, "digits": True})
        )
        result = load_config(str(cfg_path))
        assert result["length"] == 18
        assert result["digits"] is True

    def test_unknown_key_raises_config_error(self, tmp_path):
        cfg_path = tmp_path / "bad.yaml"
        cfg_path.write_text(yaml.dump({"unknown_key": "value"}))
        with pytest.raises(ConfigError, match="Unknown config keys"):
            load_config(str(cfg_path))

    def test_unsupported_extension_raises(self, tmp_path):
        cfg_path = tmp_path / "config.toml"
        cfg_path.write_text("[section]\nkey = 'value'\n")
        with pytest.raises(ConfigError, match="Unsupported config format"):
            load_config(str(cfg_path))

    def test_invalid_yaml_raises(self, tmp_path):
        cfg_path = tmp_path / "bad.yaml"
        cfg_path.write_text("{{invalid yaml")
        with pytest.raises(ConfigError, match="Invalid YAML"):
            load_config(str(cfg_path))

    def test_invalid_json_raises(self, tmp_path):
        cfg_path = tmp_path / "bad.json"
        cfg_path.write_text("{invalid json")
        with pytest.raises(ConfigError, match="Invalid JSON"):
            load_config(str(cfg_path))

    def test_non_dict_yaml_raises(self, tmp_path):
        cfg_path = tmp_path / "list.yaml"
        cfg_path.write_text("- item1\n- item2\n")
        with pytest.raises(ConfigError, match="mapping or JSON object"):
            load_config(str(cfg_path))

    def test_blank_space_mapped_to_blank(self, tmp_path):
        cfg_path = tmp_path / "blank.yaml"
        cfg_path.write_text(yaml.dump({"blank_space": True}))
        result = load_config(str(cfg_path))
        assert "blank" in result
        assert "blank_space" not in result
        assert result["blank"] is True

    def test_empty_yaml_returns_empty_dict(self, tmp_path):
        cfg_path = tmp_path / "empty.yaml"
        cfg_path.write_text("")
        result = load_config(str(cfg_path))
        assert result == {}

    def test_pattern_key_accepted(self, tmp_path):
        cfg_path = tmp_path / "pattern.yaml"
        cfg_path.write_text(yaml.dump({"pattern": "lluuddss"}))
        result = load_config(str(cfg_path))
        assert result["pattern"] == "lluuddss"

    def test_count_key_accepted(self, tmp_path):
        cfg_path = tmp_path / "count.yaml"
        cfg_path.write_text(yaml.dump({"count": 5}))
        result = load_config(str(cfg_path))
        assert result["count"] == 5

    def test_clipboard_key_accepted(self, tmp_path):
        cfg_path = tmp_path / "clip.yaml"
        cfg_path.write_text(yaml.dump({"clipboard": True}))
        result = load_config(str(cfg_path))
        assert result["clipboard"] is True

    def test_qr_key_accepted(self, tmp_path):
        cfg_path = tmp_path / "qr.yaml"
        cfg_path.write_text(yaml.dump({"qr": True}))
        result = load_config(str(cfg_path))
        assert result["qr"] is True

    def test_qr_file_key_accepted(self, tmp_path):
        cfg_path = tmp_path / "qrfile.yaml"
        cfg_path.write_text(yaml.dump({"qr_file": "out.png"}))
        result = load_config(str(cfg_path))
        assert result["qr_file"] == "out.png"


# ── CharsetConfig ────────────────────────────────────────────────────────

class TestCharsetConfig:

    def test_defaults(self):
        cfg = CharsetConfig()
        assert cfg.use_upper is False
        assert cfg.use_lower is False
        assert cfg.use_digits is False
        assert cfg.use_symbols is False
        assert cfg.allowed_symbols is None
        assert cfg.exclude_similar is False
        assert cfg.blank is False

    def test_frozen(self):
        cfg = CharsetConfig(use_upper=True)
        with pytest.raises(AttributeError):
            cfg.use_upper = False  # type: ignore[misc]

    def test_equality(self):
        a = CharsetConfig(use_upper=True, use_lower=True)
        b = CharsetConfig(use_upper=True, use_lower=True)
        assert a == b

    def test_hashable(self):
        cfg = CharsetConfig(use_upper=True)
        assert hash(cfg) is not None
        s = {cfg}
        assert cfg in s
