"""
NayVista Shield - Help & About Views
Presents comprehensive CLI command reference and verified product metadata.
"""

from scanner.config import APP_NAME, APP_TAGLINE, APP_COMPANY, APP_VERSION
from scanner.cli.theme import (
    COLOR_BRAND_YELLOW, COLOR_WHITE, COLOR_MUTED_GRAY, COLOR_RESET, colorize, BOX_HORIZ
)
from scanner.cli.terminal import (
    clear_screen, prompt_input, prompt_choice, get_terminal_width
)

def render_help() -> None:
    """Renders the CLI command reference documentation."""
    clear_screen()
    width = min(68, get_terminal_width())
    print()
    print(f"{COLOR_BRAND_YELLOW}{APP_NAME.upper()} — COMMAND REFERENCE{COLOR_RESET}")
    print(f"{COLOR_MUTED_GRAY}{BOX_HORIZ * width}{COLOR_RESET}")
    print()
    print(f"  {COLOR_BRAND_YELLOW}shield{COLOR_RESET}")
    print(f"      {COLOR_WHITE}Open interactive terminal security console (Mode A){COLOR_RESET}")
    print()
    print(f"  {COLOR_BRAND_YELLOW}shield <URL>{COLOR_RESET}")
    print(f"      {COLOR_WHITE}Start an authorized assessment directly (Mode B){COLOR_RESET}")
    print()
    print(f"  {COLOR_BRAND_YELLOW}shield <URL> --details{COLOR_RESET}")
    print(f"      {COLOR_WHITE}Display comprehensive finding descriptions and evidence{COLOR_RESET}")
    print()
    print(f"  {COLOR_BRAND_YELLOW}shield <URL> --json{COLOR_RESET}")
    print(f"      {COLOR_WHITE}Emit pure, machine-readable JSON to stdout (automation/pipeline mode){COLOR_RESET}")
    print()
    print(f"  {COLOR_BRAND_YELLOW}shield <URL> --html-report FILE{COLOR_RESET}")
    print(f"      {COLOR_WHITE}Generate print-ready HTML audit report saved to FILE{COLOR_RESET}")
    print()
    print(f"  {COLOR_BRAND_YELLOW}shield <URL> --debug{COLOR_RESET}")
    print(f"      {COLOR_WHITE}Enable diagnostic logs and sanitized execution traces{COLOR_RESET}")
    print()
    print(f"  {COLOR_BRAND_YELLOW}shield --version{COLOR_RESET}")
    print(f"      {COLOR_WHITE}Print product version and system information{COLOR_RESET}")
    print()
    print(f"  {COLOR_BRAND_YELLOW}[1]{COLOR_RESET} {COLOR_MUTED_GRAY}BACK TO MAIN MENU{COLOR_RESET}")
    print()

    prompt_choice({"1", "b", "back"}, prompt_label="NAYVISTA-SHIELD > ", default="1")

def render_about() -> None:
    """Renders official application identity, version, and defensive assessment statement."""
    clear_screen()
    width = min(68, get_terminal_width())
    print()
    print(f"{COLOR_BRAND_YELLOW}{APP_NAME.upper()}{COLOR_RESET}")
    print(f"{COLOR_WHITE}{APP_TAGLINE.upper()}{COLOR_RESET}")
    print(f"{COLOR_MUTED_GRAY}{BOX_HORIZ * width}{COLOR_RESET}")
    print()
    print(f"  {COLOR_MUTED_GRAY}Version        {COLOR_RESET} {COLOR_WHITE}{APP_VERSION}{COLOR_RESET}")
    print(f"  {COLOR_MUTED_GRAY}Assessment     {COLOR_RESET} {COLOR_WHITE}Defensive / Safe Non-Destructive{COLOR_RESET}")
    print(f"  {COLOR_MUTED_GRAY}Scope          {COLOR_RESET} {COLOR_BRAND_YELLOW}Strict Same-Origin Enforcement{COLOR_RESET}")
    print(f"  {COLOR_MUTED_GRAY}SSRF Shield    {COLOR_RESET} {COLOR_WHITE}RFC 1918 / Loopback / Cloud Metadata Protected{COLOR_RESET}")
    print(f"  {COLOR_MUTED_GRAY}Audit Pipeline {COLOR_RESET} {COLOR_WHITE}10 Automated Defensive Inspection Modules{COLOR_RESET}")
    print()
    print(f"  {COLOR_MUTED_GRAY}DEVELOPED BY{COLOR_RESET}")
    print(f"  {COLOR_BRAND_YELLOW}{APP_COMPANY.upper()}{COLOR_RESET}")
    print()
    print(f"  {COLOR_BRAND_YELLOW}[1]{COLOR_RESET} {COLOR_MUTED_GRAY}BACK TO MAIN MENU{COLOR_RESET}")
    print()

    prompt_choice({"1", "b", "back"}, prompt_label="NAYVISTA-SHIELD > ", default="1")
