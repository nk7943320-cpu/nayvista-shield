"""
NayVista Shield - Settings View
Configures terminal display preferences without exposing or weakening any security/SSRF guards.
"""

from scanner.cli.theme import (
    COLOR_BRAND_YELLOW, COLOR_WHITE, COLOR_MUTED_GRAY, COLOR_RESET, colorize
)
from scanner.cli.terminal import (
    clear_screen, prompt_input, prompt_choice
)

# In-memory session settings
SETTINGS = {
    "compact_mode": False,
    "color_enabled": True,
    "show_inventory": True,
}

def render_settings_menu() -> None:
    """Renders user preferences configuration menu."""
    while True:
        clear_screen()
        print()
        print(f"{COLOR_BRAND_YELLOW}CONSOLE SETTINGS & PREFERENCES{COLOR_RESET}")
        print()

        c_mode = "ON" if SETTINGS["compact_mode"] else "OFF"
        color_mode = "ON" if SETTINGS["color_enabled"] else "OFF"
        inv_mode = "ON" if SETTINGS["show_inventory"] else "OFF"

        print(f"  {COLOR_BRAND_YELLOW}[1]{COLOR_RESET} {COLOR_WHITE}Compact Display Mode      :{COLOR_RESET} {COLOR_BRAND_YELLOW}[ {c_mode} ]{COLOR_RESET}")
        print(f"  {COLOR_BRAND_YELLOW}[2]{COLOR_RESET} {COLOR_WHITE}Color Highlighting        :{COLOR_RESET} {COLOR_BRAND_YELLOW}[ {color_mode} ]{COLOR_RESET}")
        print(f"  {COLOR_BRAND_YELLOW}[3]{COLOR_RESET} {COLOR_WHITE}Attack Surface Inventory  :{COLOR_RESET} {COLOR_BRAND_YELLOW}[ {inv_mode} ]{COLOR_RESET}")
        print()
        print(f"  {COLOR_MUTED_GRAY}Note: Defensive security guards (SSRF, scope enforcement, authorization){COLOR_RESET}")
        print(f"  {COLOR_MUTED_GRAY}are mandatory core policies and cannot be modified or disabled.{COLOR_RESET}")
        print()
        print(f"  {COLOR_BRAND_YELLOW}[4]{COLOR_RESET} {COLOR_MUTED_GRAY}RETURN TO MAIN MENU{COLOR_RESET}")
        print()

        choice = prompt_choice({"1", "2", "3", "4", "b"}, prompt_label="NAYVISTA-SHIELD > ", default="4")
        if choice in ("4", "b"):
            return
        elif choice == "1":
            SETTINGS["compact_mode"] = not SETTINGS["compact_mode"]
        elif choice == "2":
            SETTINGS["color_enabled"] = not SETTINGS["color_enabled"]
        elif choice == "3":
            SETTINGS["show_inventory"] = not SETTINGS["show_inventory"]
