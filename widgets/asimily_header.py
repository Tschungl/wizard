# widgets/asimily_header.py
from __future__ import annotations
import pyfiglet
from textual.widgets import Static

_ASCII = pyfiglet.figlet_format("Asimily Wizard", font="small")


class AsimilyHeader(Static):
    """Full-width green ASCII-art header shown on every screen."""

    DEFAULT_CSS = """
    AsimilyHeader {
        color: #22c55e;
        text-style: bold;
        width: 100%;
        padding: 0 2;
    }
    """

    def __init__(self) -> None:
        super().__init__(_ASCII)
