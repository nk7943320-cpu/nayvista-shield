"""
NayVista Shield - Main Menu View
Renders the numbered navigation menu for the interactive security console.
"""

from scanner.config import APP_NAME
from scanner.cli.theme import (
    COLOR_BRAND_YELLOW, COLOR_WHITE, COLOR_MUTED_GRAY, COLOR_RESET, colorize
)
from scanner.cli.terminal import (
    make_box_top, make_box_bottom, format_box_row, prompt_choice
)

MENU_ITEMS = [
    ("01", "NEW SECURITY ASSESSMENT"),
    ("02", "SCAN HISTORY"),
    ("03", "TARGET HISTORY"),
    ("04", "REPORTS"),
    ("05", "SETTINGS"),
    ("06", "HELP"),
    ("07", "ABOUT"),
    ("08", "EXIT"),
]

def render_main_menu(width: int = 60) -> str:
    """
    Renders the main menu box and waits for user choice.
    Returns the selected option string ("1" to "8" or "01" to "08").
    """
    box_title = f"{APP_NAME.upper()}"
    print(make_box_top(width, title=box_title))
    print(format_box_row("", width))

    for num, label in MENU_ITEMS:
        item_str = f"  {COLOR_BRAND_YELLOW}{num}{COLOR_RESET}  {COLOR_WHITE}{label}{COLOR_RESET}"
        print(format_box_row(item_str, width))

    print(format_box_row("", width))
    print(make_box_bottom(width))
    print()

    valid_choices = {item[0] for item in MENU_ITEMS} | {str(int(item[0])) for item in MENU_ITEMS}
    choice = prompt_choice(valid_choices, prompt_label="NAYVISTA-SHIELD > ")
    return choice.zfill(2)
