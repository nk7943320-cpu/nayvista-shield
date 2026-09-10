"""
NayVista Shield - Error & Interruption Views
Provides clean, structured error cards replacing raw tracebacks, and handles graceful Ctrl+C cancellation.
"""

from typing import Optional
from scanner.cli.theme import (
    COLOR_BRAND_YELLOW, COLOR_WHITE, COLOR_MUTED_GRAY, COLOR_RED, COLOR_RESET, colorize,
    BOX_DIVIDER_LEFT, BOX_DIVIDER_RIGHT
)
from scanner.cli.terminal import (
    clear_screen, get_terminal_width, make_box_top, make_box_bottom,
    make_box_divider, format_box_row, wrap_text_lines, prompt_choice
)

def render_error_panel(title: str, message: str, code: Optional[str] = None, width: int = 60) -> str:
    """
    Renders a formatted error panel with recovery choices:
    [1] TRY ANOTHER TARGET
    [2] RETURN TO MENU
    [3] EXIT
    """
    clear_screen()
    width = min(width, get_terminal_width())
    code_str = f" [CODE: {code}]" if code else ""

    print()
    print(make_box_top(width))
    header = f"{COLOR_RED}{title.upper()}{code_str}{COLOR_RESET}"
    print(format_box_row(header, width))
    print(make_box_divider(width))
    print(format_box_row("", width))

    for line in wrap_text_lines(message, width - 6):
        print(format_box_row(f"  {COLOR_WHITE}{line}{COLOR_RESET}", width))

    print(format_box_row("", width))
    print(make_box_bottom(width))
    print()
    print(f"  {COLOR_BRAND_YELLOW}[1]{COLOR_RESET} {COLOR_WHITE}TRY ANOTHER TARGET{COLOR_RESET}")
    print(f"  {COLOR_BRAND_YELLOW}[2]{COLOR_RESET} {COLOR_WHITE}RETURN TO MAIN MENU{COLOR_RESET}")
    print(f"  {COLOR_BRAND_YELLOW}[3]{COLOR_RESET} {COLOR_MUTED_GRAY}EXIT{COLOR_RESET}")
    print()

    return prompt_choice({"1", "2", "3"}, prompt_label="NAYVISTA-SHIELD > ", default="2")

def render_interrupted_panel(target: str, step: int, total_steps: int, findings_count: int, width: int = 60) -> str:
    """
    Renders clean cancellation screen upon KeyboardInterrupt / Ctrl+C.
    Returns:
      "1" -> RETURN TO MENU
      "2" -> EXIT
    """
    clear_screen()
    width = min(width, get_terminal_width())

    print()
    print(make_box_top(width))
    header = f"{COLOR_BRAND_YELLOW}ASSESSMENT INTERRUPTED{COLOR_RESET}"
    print(format_box_row(header, width))
    print(make_box_divider(width))
    print(format_box_row("", width))

    print(format_box_row(f"  {COLOR_MUTED_GRAY}Target   :{COLOR_RESET} {COLOR_WHITE}{target[:width-16]}{COLOR_RESET}", width))
    print(format_box_row(f"  {COLOR_MUTED_GRAY}Progress :{COLOR_RESET} {COLOR_WHITE}{step} / {total_steps}{COLOR_RESET}", width))
    print(format_box_row(f"  {COLOR_MUTED_GRAY}Findings :{COLOR_RESET} {COLOR_WHITE}{findings_count}{COLOR_RESET}", width))
    print(format_box_row("", width))
    print(make_box_bottom(width))
    print()
    print(f"  {COLOR_BRAND_YELLOW}[1]{COLOR_RESET} {COLOR_WHITE}RETURN TO MAIN MENU{COLOR_RESET}")
    print(f"  {COLOR_BRAND_YELLOW}[2]{COLOR_RESET} {COLOR_MUTED_GRAY}EXIT{COLOR_RESET}")
    print()

    return prompt_choice({"1", "2"}, prompt_label="NAYVISTA-SHIELD > ", default="2")
