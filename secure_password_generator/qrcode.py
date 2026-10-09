"""
QR code generation, reading, and display via segno and pyrxing.
"""

from pathlib import Path

import segno
from pyrxing import read_barcode


def display_qr(text: str) -> None:
    """Print a QR code to the terminal using Unicode blocks."""
    qr = segno.make(text)
    qr.terminal(compact=True)


def save_qr(text: str, path: str, scale: int = 5) -> None:
    """Save a QR code as a PNG file."""
    qr = segno.make(text)
    qr.save(path, scale=scale)


def read_qr(path: str) -> str:
    """Decode a QR code image and return the embedded text.

    Uses ``pyrxing`` (zxing-cpp via Rust bindings) to decode the image.
    Only QR codes are searched — other barcode formats are ignored.

    Args:
        path: Path to the QR code image file.

    Returns:
        The decoded text string from the QR code.

    Raises:
        FileNotFoundError: If the file does not exist.
        ValueError: If the image contains no readable QR code.
    """
    resolved = Path(path).resolve()
    if not resolved.exists():
        raise FileNotFoundError(f"QR file not found: {path}")
    result = read_barcode(str(resolved), formats=["QRCode"])
    if result is None:
        raise ValueError(f"No QR code found in: {path}")
    return result.text
