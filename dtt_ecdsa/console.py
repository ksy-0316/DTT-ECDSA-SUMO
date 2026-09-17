"""Console helper.

Windows consoles frequently run a legacy code page (GBK on Simplified-Chinese
systems).  Printing a character the code page cannot represent raises
``UnicodeEncodeError`` and aborts the program, so the output streams are made
tolerant here.  The scheme output deliberately sticks to characters that both
GBK and UTF-8 can represent, and this shim only guards against surprises.
"""

from __future__ import annotations

import sys
import unicodedata


def setup_console() -> None:
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(errors="replace")
        except (AttributeError, ValueError, OSError):
            pass


def safe_print(text: str = "") -> None:
    """``print`` that never dies on an un-encodable character."""
    try:
        print(text)
    except UnicodeEncodeError:
        enc = getattr(sys.stdout, "encoding", None) or "utf-8"
        print(text.encode(enc, errors="replace").decode(enc, errors="replace"))


def display_width(text: str) -> int:
    """Column width of ``text``; CJK / full-width characters count as two."""
    return sum(2 if unicodedata.east_asian_width(c) in ("W", "F") else 1
               for c in text)


def pad(text: str, width: int, align: str = "<") -> str:
    """Pad ``text`` to ``width`` display columns (CJK aware)."""
    fill = " " * max(0, width - display_width(text))
    return text + fill if align == "<" else fill + text

