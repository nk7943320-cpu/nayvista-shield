"""
NayVista Shield - Central Terminal Theme & Styling
Defines palette, brand colors, Unicode/ASCII glyphs, and severity formatters.
Palette: Black, Yellow/Amber, White, Muted Gray.
"""

import sys
from typing import Tuple

# Detect UTF-8 capability
CAN_UTF8 = bool(sys.stdout.encoding and "utf" in sys.stdout.encoding.lower())

# Color definitions
COLOR_BRAND_YELLOW = "\033[1;33m"      # Bright/Bold Yellow
COLOR_AMBER        = "\033[38;5;214m"   # Amber
COLOR_WHITE        = "\033[1;37m"      # Bold White
COLOR_MUTED_GRAY   = "\033[38;5;244m"   # Muted Warm Gray
COLOR_DIM          = "\033[2m"          # Dim
COLOR_RESET        = "\033[0m"          # Reset
COLOR_RED          = "\033[1;31m"      # Bold Red
COLOR_ORANGE       = "\033[38;5;208m"   # Orange
COLOR_GREEN        = "\033[1;32m"      # Bold Green
COLOR_CYAN         = "\033[1;36m"      # Bold Cyan

# Box Drawing Elements
if CAN_UTF8:
    BOX_TOP_LEFT     = "┌"
    BOX_TOP_RIGHT    = "┐"
    BOX_BOTTOM_LEFT  = "└"
    BOX_BOTTOM_RIGHT = "┘"
    BOX_HORIZ        = "─"
    BOX_VERT         = "│"
    BOX_DOUBLE_TOP   = "╔"
    BOX_DOUBLE_TR    = "╗"
    BOX_DOUBLE_BL    = "╚"
    BOX_DOUBLE_BR    = "╝"
    BOX_DOUBLE_H     = "═"
    BOX_DOUBLE_V     = "║"
    BOX_DIVIDER_LEFT = "├"
    BOX_DIVIDER_RIGHT= "┤"
    GLYPH_CHECK      = "✓"
    GLYPH_RUNNING    = "●"
    GLYPH_WAITING    = "○"
    GLYPH_FAILED     = "✗"
    GLYPH_WARN       = "!"
    GLYPH_DOT        = "•"
    PROGRESS_FULL    = "█"
    PROGRESS_EMPTY   = "░"
else:
    BOX_TOP_LEFT     = "+"
    BOX_TOP_RIGHT    = "+"
    BOX_BOTTOM_LEFT  = "+"
    BOX_BOTTOM_RIGHT = "+"
    BOX_HORIZ        = "-"
    BOX_VERT         = "|"
    BOX_DOUBLE_TOP   = "+"
    BOX_DOUBLE_TR    = "+"
    BOX_DOUBLE_BL    = "+"
    BOX_DOUBLE_BR    = "+"
    BOX_DOUBLE_H     = "="
    BOX_DOUBLE_V     = "|"
    BOX_DIVIDER_LEFT = "+"
    BOX_DIVIDER_RIGHT= "+"
    GLYPH_CHECK      = "[OK]"
    GLYPH_RUNNING    = "[*]"
    GLYPH_WAITING    = "[-]"
    GLYPH_FAILED     = "[X]"
    GLYPH_WARN       = "[!]"
    GLYPH_DOT        = "*"
    PROGRESS_FULL    = "#"
    PROGRESS_EMPTY   = "-"

# Severity text representations (accessible without color)
SEVERITY_BADGES = {
    "CRITICAL": "[CRITICAL]",
    "HIGH":     "[HIGH]",
    "MEDIUM":   "[MEDIUM]",
    "LOW":      "[LOW]",
    "INFO":     "[INFO]",
}

SEVERITY_COLORS = {
    "CRITICAL": COLOR_RED,
    "HIGH":     COLOR_ORANGE,
    "MEDIUM":   COLOR_BRAND_YELLOW,
    "LOW":      COLOR_GREEN,
    "INFO":     COLOR_MUTED_GRAY,
}

import os

# Check standard NO_COLOR specification (no-color.org)
NO_COLOR = bool(os.environ.get("NO_COLOR") or os.environ.get("TERM") == "dumb")

def format_severity(severity: str, use_color: bool = True) -> str:
    """Formats a severity level with text badge and optional color."""
    sev = severity.upper()
    badge = SEVERITY_BADGES.get(sev, f"[{sev}]")
    if not use_color or NO_COLOR:
        return badge
    color = SEVERITY_COLORS.get(sev, COLOR_WHITE)
    return f"{color}{badge}{COLOR_RESET}"

def colorize(text: str, color_code: str, use_color: bool = True) -> str:
    """Applies ANSI color code if color is enabled and NO_COLOR is unset."""
    if not use_color or NO_COLOR:
        return text
    return f"{color_code}{text}{COLOR_RESET}"
