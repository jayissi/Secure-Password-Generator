"""
QR code generation for passwords via segno.
"""

import segno


def display_qr(text: str) -> None:
    """Print a QR code to the terminal using Unicode blocks."""
    qr = segno.make(text)
    qr.terminal(compact=True)


def save_qr(text: str, path: str, scale: int = 5) -> None:
    """Save a QR code as a PNG file."""
    qr = segno.make(text)
    qr.save(path, scale=scale)
