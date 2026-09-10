"""
NayVista Shield - Startup View
Renders the startup screen with compact brand banner and verified system component readiness.
"""

from typing import Dict
from scanner.config import APP_NAME, APP_TAGLINE, APP_COMPANY
from scanner.cli.theme import (
    COLOR_BRAND_YELLOW, COLOR_WHITE, COLOR_MUTED_GRAY, COLOR_GREEN, COLOR_RED, COLOR_RESET, colorize
)
from scanner.cli.terminal import (
    get_terminal_width, make_box_top, make_box_bottom, format_box_row
)

def check_system_readiness() -> Dict[str, bool]:
    """Inspects and verifies actual module import and initialization readiness."""
    status = {}

    # Core Engine
    try:
        from scanner.engine import ScannerEngine
        status["CORE ENGINE"] = True
    except Exception:
        status["CORE ENGINE"] = False

    # Scope Guard & SSRF Protection
    try:
        from scanner.scope import TargetScope, TargetSSRFBlockedError
        status["SCOPE GUARD"] = True
    except Exception:
        status["SCOPE GUARD"] = False

    # TLS Analyzer
    try:
        import ssl
        from scanner.modules.tls import TLSScanner
        status["TLS ANALYZER"] = True
    except Exception:
        status["TLS ANALYZER"] = False

    # Finding Engine
    try:
        from scanner.findings import generate_finding_id, deduplicate_findings
        status["FINDING ENGINE"] = True
    except Exception:
        status["FINDING ENGINE"] = False

    # Report Engine
    try:
        from scanner.report import generate_json_report, generate_html_report
        status["REPORT ENGINE"] = True
    except Exception:
        status["REPORT ENGINE"] = False

    return status

def render_startup_screen(width: int = 60) -> None:
    """Renders the compact, premium startup banner and actual initialization readiness."""
    print()
    print(make_box_top(width))
    print(format_box_row("", width))

    title_text = colorize(APP_NAME.upper(), COLOR_BRAND_YELLOW)
    print(format_box_row(f"{' ' * max(0, (width - 4 - len(APP_NAME)) // 2)}{title_text}", width))
    print(format_box_row("", width))

    tag_text = colorize(APP_TAGLINE.upper(), COLOR_WHITE)
    print(format_box_row(f"{' ' * max(0, (width - 4 - len(APP_TAGLINE)) // 2)}{tag_text}", width))
    print(format_box_row("", width))

    comp_text = colorize(f"DEVELOPED BY {APP_COMPANY.upper()}", COLOR_MUTED_GRAY)
    print(format_box_row(f"{' ' * max(0, (width - 4 - len('DEVELOPED BY ' + APP_COMPANY)) // 2)}{comp_text}", width))
    print(format_box_row("", width))

    print(make_box_bottom(width))
    print()

    # Actual subsystem readiness checks
    readiness = check_system_readiness()
    all_ready = all(readiness.values())

    for component, is_ready in readiness.items():
        if is_ready:
            badge = f"{COLOR_GREEN}[ READY ]{COLOR_RESET}"
        else:
            badge = f"{COLOR_RED}[ FAILED ]{COLOR_RESET}"
        print(f"  {COLOR_MUTED_GRAY}{component:<18}{COLOR_RESET} {badge}")

    print()
    if all_ready:
        print(f"  {COLOR_WHITE}SYSTEM STATUS{COLOR_RESET}      {COLOR_BRAND_YELLOW}OPERATIONAL{COLOR_RESET}")
    else:
        print(f"  {COLOR_WHITE}SYSTEM STATUS{COLOR_RESET}      {COLOR_RED}DEGRADED{COLOR_RESET}")
    print()
