"""
NayVista Shield - Target Review & Authorization View
Parses target URL, presents security parameters, and enforces explicit authorization.
"""

from urllib.parse import urlparse
from typing import Tuple, Optional
from scanner.cli.theme import (
    COLOR_BRAND_YELLOW, COLOR_WHITE, COLOR_MUTED_GRAY, COLOR_RESET, colorize,
    BOX_HORIZ
)
from scanner.cli.terminal import (
    clear_screen, prompt_input, prompt_choice, get_terminal_width
)

def prompt_target_url() -> str:
    """Displays the new assessment prompt and requests target URL from user."""
    clear_screen()
    width = min(60, get_terminal_width())
    print()
    print(f"{COLOR_BRAND_YELLOW}NEW SECURITY ASSESSMENT{COLOR_RESET}")
    print(f"{COLOR_MUTED_GRAY}{BOX_HORIZ * width}{COLOR_RESET}")
    print()

    url = prompt_input("TARGET URL > ")
    return url.strip()

def render_target_review(target_url: str, is_direct: bool = False, mode: str = "defensive") -> str:
    """
    Renders target review with protocol, origin, scope, and authorization options.
    Returns:
      "1" -> AUTHORIZE & START
      "2" -> CHANGE TARGET (or CANCEL in direct mode)
      "3" -> CANCEL
    """
    clear_screen()
    width = min(64, get_terminal_width())

    parsed = urlparse(target_url)
    scheme = parsed.scheme.upper() if parsed.scheme else "HTTPS"
    hostname = parsed.hostname or target_url
    port = parsed.port or (443 if scheme == "HTTPS" else 80)
    origin = f"{hostname}:{port}" if parsed.port else hostname

    is_active = mode.lower() in ("active", "authorized", "active / authorized testing")
    mode_label = "ACTIVE / AUTHORIZED TESTING" if is_active else "DEFENSIVE / SAFE"

    print()
    if is_direct:
        print(f"{COLOR_BRAND_YELLOW}NAYVISTA SHIELD{COLOR_RESET}")
        print(f"{COLOR_MUTED_GRAY}{BOX_HORIZ * width}{COLOR_RESET}")
        print()
        print(f"  {COLOR_MUTED_GRAY}TARGET  ::{COLOR_RESET} {COLOR_WHITE}{target_url}{COLOR_RESET}")
        print(f"  {COLOR_MUTED_GRAY}SCOPE   ::{COLOR_RESET} {COLOR_BRAND_YELLOW}SAME-ORIGIN{COLOR_RESET}")
        print(f"  {COLOR_MUTED_GRAY}MODE    ::{COLOR_RESET} {COLOR_WHITE}{mode_label}{COLOR_RESET}")
        if is_active:
            print(f"  {COLOR_MUTED_GRAY}SAFETY  ::{COLOR_RESET} {COLOR_BRAND_YELLOW}Bounded (Max 4 conc, 100 reqs, Non-destructive){COLOR_RESET}")
        print()
        print(f"  {COLOR_BRAND_YELLOW}AUTHORIZATION REQUIRED{COLOR_RESET}")
        if is_active:
            print(f"  {COLOR_MUTED_GRAY}Active testing requires explicit operator authorization confirmation.{COLOR_RESET}")
        print()
        print(f"  {COLOR_BRAND_YELLOW}[1]{COLOR_RESET} {COLOR_WHITE}AUTHORIZE & START{COLOR_RESET}")
        print(f"  {COLOR_BRAND_YELLOW}[2]{COLOR_RESET} {COLOR_MUTED_GRAY}CANCEL{COLOR_RESET}")
        print()
        choice = prompt_choice({"1", "2", "y", "n", "yes", "no"}, prompt_label="NAYVISTA-SHIELD > ", default="1")
        if choice in ("1", "y", "yes"):
            return "1"
        return "2"
    else:
        print(f"{COLOR_BRAND_YELLOW}TARGET REVIEW{COLOR_RESET}")
        print(f"{COLOR_MUTED_GRAY}{BOX_HORIZ * width}{COLOR_RESET}")
        print()
        print(f"  {COLOR_MUTED_GRAY}TARGET      {COLOR_RESET} {COLOR_WHITE}{target_url}{COLOR_RESET}")
        print(f"  {COLOR_MUTED_GRAY}ORIGIN      {COLOR_RESET} {COLOR_WHITE}{origin}{COLOR_RESET}")
        print(f"  {COLOR_MUTED_GRAY}PROTOCOL    {COLOR_RESET} {COLOR_WHITE}{scheme}{COLOR_RESET}")
        print(f"  {COLOR_MUTED_GRAY}PORT        {COLOR_RESET} {COLOR_WHITE}{port}{COLOR_RESET}")
        print(f"  {COLOR_MUTED_GRAY}SCOPE       {COLOR_RESET} {COLOR_BRAND_YELLOW}SAME-ORIGIN{COLOR_RESET}")
        print(f"  {COLOR_MUTED_GRAY}MODE        {COLOR_RESET} {COLOR_WHITE}{mode_label}{COLOR_RESET}")
        if is_active:
            print(f"  {COLOR_MUTED_GRAY}SAFETY      {COLOR_RESET} {COLOR_BRAND_YELLOW}Bounded (Max 4 conc, 100 reqs, Non-destructive){COLOR_RESET}")
        print()
        print(f"  {COLOR_BRAND_YELLOW}AUTHORIZATION REQUIRED{COLOR_RESET}")
        if is_active:
            print(f"  {COLOR_MUTED_GRAY}Active mode requires formal confirmation of authorized testing.{COLOR_RESET}")
        print()
        print(f"  {COLOR_BRAND_YELLOW}[1]{COLOR_RESET} {COLOR_WHITE}AUTHORIZE & START{COLOR_RESET}")
        print(f"  {COLOR_BRAND_YELLOW}[2]{COLOR_RESET} {COLOR_WHITE}CHANGE TARGET{COLOR_RESET}")
        print(f"  {COLOR_BRAND_YELLOW}[3]{COLOR_RESET} {COLOR_MUTED_GRAY}CANCEL{COLOR_RESET}")
        print()
        choice = prompt_choice({"1", "2", "3", "y", "n"}, prompt_label="NAYVISTA-SHIELD > ", default="1")
        if choice in ("1", "y"):
            return "1"
        elif choice == "2":
            return "2"
        return "3"
