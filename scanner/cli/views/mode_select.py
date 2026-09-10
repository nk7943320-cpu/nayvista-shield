"""
NayVista Shield - Assessment Mode Selection View
Allows operator to select assessment mode.
DEFENSIVE / SAFE is fully functional.
ATTACK SIMULATION is visible but clearly disabled with:
"Coming in a future authorized-testing phase".
"""

from scanner.cli.theme import (
    COLOR_BRAND_YELLOW, COLOR_WHITE, COLOR_MUTED_GRAY, COLOR_RED, COLOR_GREEN, COLOR_RESET, colorize,
    BOX_HORIZ
)
from scanner.cli.terminal import (
    clear_screen, prompt_choice, pause, get_terminal_width
)

def prompt_assessment_mode() -> str:
    """
    Renders assessment mode selector.
    Returns:
      "defensive", "active", or "cancel"
    """
    while True:
        clear_screen()
        width = min(68, get_terminal_width())
        print()
        print(f"{COLOR_BRAND_YELLOW}SELECT ASSESSMENT MODE{COLOR_RESET}")
        print(f"{COLOR_MUTED_GRAY}{BOX_HORIZ * width}{COLOR_RESET}")
        print()
        print(f"  {COLOR_BRAND_YELLOW}[01]{COLOR_RESET} {COLOR_WHITE}DEFENSIVE / SAFE{COLOR_RESET} {COLOR_GREEN}[ACTIVE]{COLOR_RESET}")
        print(f"       {COLOR_MUTED_GRAY}Passive audit: DNS & IP analysis, standard service port exposure,{COLOR_RESET}")
        print(f"       {COLOR_MUTED_GRAY}HTTP headers, TLS ciphers, cookies, crawl & surface inventory.{COLOR_RESET}")
        print(f"       {COLOR_MUTED_GRAY}Zero exploitation, zero fuzzing, zero destructive traffic.{COLOR_RESET}")
        print()
        print(f"  {COLOR_BRAND_YELLOW}[02]{COLOR_RESET} {COLOR_WHITE}ACTIVE / AUTHORIZED TESTING{COLOR_RESET} {COLOR_GREEN}[ACTIVE]{COLOR_RESET}")
        print(f"       {COLOR_MUTED_GRAY}Bounded active validation: HTTP behavior, TLS strength, CORS,{COLOR_RESET}")
        print(f"       {COLOR_MUTED_GRAY}API security, auth review, access controls, infrastructure exposures.{COLOR_RESET}")
        print(f"       {COLOR_MUTED_GRAY}Non-destructive, rate-governed, auditable evidence collection.{COLOR_RESET}")
        print()
        print(f"  {COLOR_MUTED_GRAY}[03] ATTACK SIMULATION{COLOR_RESET} {COLOR_RED}[DISABLED]{COLOR_RESET}")
        print(f"       {COLOR_MUTED_GRAY}Coming in a future authorized-testing phase.{COLOR_RESET}")
        print(f"       {COLOR_MUTED_GRAY}Includes exploit validation, active payload verification, and brute force.{COLOR_RESET}")
        print()
        print(f"  {COLOR_BRAND_YELLOW}[B] {COLOR_RESET} {COLOR_MUTED_GRAY}BACK / CANCEL{COLOR_RESET}")
        print()

        choice = prompt_choice({"1", "01", "defensive", "2", "02", "active", "authorized", "3", "03", "attack", "simulation", "b", "back", "cancel"}, prompt_label="MODE > ", default="1")
        if choice in ("1", "01", "defensive"):
            return "defensive"
        elif choice in ("2", "02", "active", "authorized"):
            return "active"
        elif choice in ("3", "03", "attack", "simulation"):
            print()
            print(f"  {COLOR_RED}[!] ATTACK SIMULATION mode is disabled in this release.{COLOR_RESET}")
            print(f"  {COLOR_MUTED_GRAY}    This capability is reserved for a future authorized-testing phase.{COLOR_RESET}")
            print(f"  {COLOR_MUTED_GRAY}    NayVista Shield currently executes in DEFENSIVE and ACTIVE modes.{COLOR_RESET}")
            print()
            pause()
            continue
        elif choice in ("b", "back", "cancel"):
            return "cancel"
