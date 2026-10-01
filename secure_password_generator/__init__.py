"""
Secure Password Generator — cryptographically strong passwords with
AES-GCM-SIV encrypted vault storage.
"""

__version__ = "2.0.0"

from secure_password_generator.config import CharsetConfig, ConfigError
from secure_password_generator.crypto import (
    decrypt_data,
    encrypt_data,
    get_encryption_key,
)
from secure_password_generator.generator import (
    build_charset,
    calculate_password_strength,
    compute_charset_size,
    expected_unique_chars,
    format_strength_meter,
    generate_password,
)

__all__ = [
    "CharsetConfig",
    "ConfigError",
    "build_charset",
    "calculate_password_strength",
    "compute_charset_size",
    "decrypt_data",
    "encrypt_data",
    "expected_unique_chars",
    "format_strength_meter",
    "generate_password",
    "get_encryption_key",
]
