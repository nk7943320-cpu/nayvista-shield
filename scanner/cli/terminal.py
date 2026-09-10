"""
NayVista Shield - Terminal Utilities
Provides cross-platform screen clearing, column width detection, box formatting, and input helpers.
Supports Windows CMD, PowerShell, Windows Terminal, Linux, Kali Linux, Termux, and macOS.
"""

import os
import sys
import shutil
import textwrap
from typing import List, Optional, Set

from scanner.cli.theme import (
    BOX_VERT, BOX_HORIZ, BOX_TOP_LEFT, BOX_TOP_RIGHT,
    BOX_BOTTOM_LEFT, BOX_BOTTOM_RIGHT, BOX_DIVIDER_LEFT, BOX_DIVIDER_RIGHT,
    COLOR_BRAND_YELLOW, COLOR_MUTED_GRAY, COLOR_WHITE, COLOR_RESET, colorize
)

def get_terminal_width(default: int = 80) -> int:
    """Returns the current terminal column width, clamped between 60 and 160."""
    try:
        cols, _ = shutil.get_terminal_size(fallback=(default, 24))
        return max(60, min(cols, 160))
    except Exception:
        return default

def clear_screen() -> None:
    """
    Clears the visible terminal screen cross-platform.
    Uses ANSI escape codes with fallback to system commands (cls / clear).
    """
    # Try ANSI clear sequence (works in Windows Terminal, PowerShell, modern CMD, Linux, macOS, Termux)
    try:
        sys.stdout.write("\033[2J\033[H\033[3J")
        sys.stdout.flush()
    except Exception:
        pass

    # Run system command as well for older CMD or shells without ANSI support
    try:
        if os.name == "nt":
            os.system("cls")
        else:
            os.system("clear")
    except Exception:
        # Fallback: print newlines if terminal clearing is unavailable
        sys.stdout.write("\n" * 40)
        sys.stdout.flush()

def make_box_top(width: int, title: str = "", use_color: bool = True) -> str:
    """Builds a top border line with optional title."""
    if title:
        inner_title = f" {title} "
        rem = max(0, width - 2 - len(inner_title))
        line = f"{BOX_TOP_LEFT}{BOX_HORIZ * 2}{inner_title}{BOX_HORIZ * (rem - 2)}{BOX_TOP_RIGHT}"
    else:
        line = f"{BOX_TOP_LEFT}{BOX_HORIZ * (width - 2)}{BOX_TOP_RIGHT}"
    return colorize(line, COLOR_BRAND_YELLOW, use_color)

def make_box_bottom(width: int, use_color: bool = True) -> str:
    """Builds a bottom border line."""
    line = f"{BOX_BOTTOM_LEFT}{BOX_HORIZ * (width - 2)}{BOX_BOTTOM_RIGHT}"
    return colorize(line, COLOR_BRAND_YELLOW, use_color)

def make_box_divider(width: int, use_color: bool = True) -> str:
    """Builds an inner horizontal divider."""
    line = f"{BOX_DIVIDER_LEFT}{BOX_HORIZ * (width - 2)}{BOX_DIVIDER_RIGHT}"
    return colorize(line, COLOR_BRAND_YELLOW, use_color)

def format_box_row(content: str, width: int, use_color: bool = True, pad_char: str = " ") -> str:
    """Formats a single content line enclosed in side borders."""
    inner_width = max(0, width - 4)
    visible_len = len(strip_ansi(content))
    if visible_len > inner_width:
        content = content[:inner_width]
        visible_len = len(strip_ansi(content))
    pad_needed = max(0, inner_width - visible_len)
    side = colorize(BOX_VERT, COLOR_BRAND_YELLOW, use_color)
    return f"{side} {content}{pad_char * pad_needed} {side}"

def strip_ansi(text: str) -> str:
    """Strips ANSI escape codes from string for length calculation."""
    import re
    ansi_regex = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
    return ansi_regex.sub('', text)

def wrap_text_lines(text: str, max_width: int) -> List[str]:
    """Wraps text cleanly into lines respecting maximum column width."""
    lines = []
    for paragraph in text.splitlines():
        if not paragraph.strip():
            lines.append("")
            continue
        wrapped = textwrap.wrap(paragraph, width=max_width)
        lines.extend(wrapped)
    return lines

def prompt_input(prompt_label: str = "NAYVISTA-SHIELD > ") -> str:
    """Prompts the user for a text input cleanly."""
    try:
        formatted_prompt = f"{COLOR_BRAND_YELLOW}{prompt_label}{COLOR_RESET}"
        return input(formatted_prompt).strip()
    except (EOFError, KeyboardInterrupt):
        return ""

def prompt_choice(valid_choices: Set[str], prompt_label: str = "NAYVISTA-SHIELD > ", default: Optional[str] = None) -> str:
    """Prompts for one of the valid numbered choices, with optional default."""
    while True:
        try:
            val = prompt_input(prompt_label)
            if not val and default is not None:
                return default
            # Normalize e.g. "01" -> "1" and check membership
            val_norm = val.lstrip("0") if val.isdigit() and val != "0" else val
            if val in valid_choices or val_norm in valid_choices:
                return val_norm if val_norm in valid_choices else val
            print(f"  {COLOR_MUTED_GRAY}Invalid option. Enter one of {sorted(list(valid_choices))}{COLOR_RESET}")
        except (EOFError, KeyboardInterrupt):
            return "EXIT" if "EXIT" in valid_choices or "exit" in valid_choices else ""

def pause(prompt_label: str = "Press Enter to continue...") -> None:
    """Waits for the user to press Enter."""
    try:
        input(f"  {COLOR_MUTED_GRAY}{prompt_label}{COLOR_RESET}")
    except (EOFError, KeyboardInterrupt):
        pass
