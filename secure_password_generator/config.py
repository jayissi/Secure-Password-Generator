"""
Configuration: CharsetConfig dataclass, YAML/JSON config file loader, ConfigError.
"""

import dataclasses
import json
from pathlib import Path
from typing import Any

import yaml

from secure_password_generator.constants import (
    CONFIG_KEY_MAP,
    VALID_CONFIG_KEYS,
)


class ConfigError(Exception):
    """Raised when a configuration file cannot be loaded or is invalid."""


@dataclasses.dataclass(frozen=True)
class CharsetConfig:
    """Immutable specification for the character pool used during generation."""

    use_upper: bool = False
    use_lower: bool = False
    use_digits: bool = False
    use_symbols: bool = False
    allowed_symbols: str | None = None
    exclude_similar: bool = False
    blank: bool = False
    latin_ext: bool = False


def load_config(config_path: str) -> dict[str, Any]:
    """Load and validate a YAML or JSON config file.

    Format is auto-detected by file extension (.yaml/.yml for YAML,
    .json for JSON).  All fields are optional; unknown keys raise
    :class:`ConfigError`.

    Args:
        config_path: Path to the config file.

    Returns:
        Dictionary of config values with keys mapped to argparse dest names.

    Raises:
        ConfigError: If the file is missing, has an unsupported format,
            contains invalid syntax, or includes unknown keys.
    """
    path = Path(config_path)
    if not path.exists():
        raise ConfigError(f"Config file not found: {config_path}")

    suffix = path.suffix.lower()

    try:
        with open(path) as f:
            if suffix in (".yaml", ".yml"):
                config = yaml.safe_load(f) or {}
            elif suffix == ".json":
                config = json.load(f)
            else:
                raise ConfigError(
                    f"Unsupported config format '{suffix}'. "
                    "Use .yaml, .yml, or .json"
                )
    except yaml.YAMLError as exc:
        raise ConfigError(f"Invalid YAML in config file: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise ConfigError(f"Invalid JSON in config file: {exc}") from exc

    if not isinstance(config, dict):
        raise ConfigError(
            "Config file must contain a YAML mapping or JSON object"
        )

    unknown = set(config.keys()) - VALID_CONFIG_KEYS
    if unknown:
        raise ConfigError(
            f"Unknown config keys: {', '.join(sorted(unknown))}"
        )

    mapped: dict[str, Any] = {}
    for key, value in config.items():
        dest = CONFIG_KEY_MAP.get(str(key), str(key))
        mapped[dest] = value

    return mapped
