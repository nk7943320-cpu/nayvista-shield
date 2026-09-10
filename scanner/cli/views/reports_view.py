"""
NayVista Shield - Reports View
Lists completed assessments and provides instant HTML/JSON audit report generation without re-scanning.
"""

from scanner.cli.theme import (
    COLOR_BRAND_YELLOW, COLOR_WHITE, COLOR_MUTED_GRAY, COLOR_RESET, colorize
)
from scanner.cli.terminal import (
    clear_screen, prompt_input, prompt_choice
)
from scanner.cli.history import load_history
from scanner.cli.views.history_view import _export_scan_report

def render_reports_menu() -> None:
    """Displays available assessment reports from history and provides export actions."""
    while True:
        clear_screen()
        history = load_history()
        print()
        print(f"{COLOR_BRAND_YELLOW}REPORTS{COLOR_RESET}")
        print()

        if not history:
            print(f"  {COLOR_MUTED_GRAY}NO PREVIOUS ASSESSMENTS AVAILABLE FOR REPORTING{COLOR_RESET}")
            print()
            prompt_input("Press Enter to return > ")
            return

        for idx, scan in enumerate(history[:15]):
            hostname = scan.get("hostname", "target")
            date_str = (scan.get("created_at") or "")[:10]
            score_str = f"Score {scan.get('score', 100)}/100"
            print(f"  {COLOR_BRAND_YELLOW}[{idx + 1:02d}]{COLOR_RESET} {COLOR_WHITE}{hostname:<24}{COLOR_RESET} — {COLOR_MUTED_GRAY}Security Assessment ({date_str}, {score_str}){COLOR_RESET}")

        print()
        print(f"  {COLOR_MUTED_GRAY}Enter report number (1-{min(len(history), 15)}) or B to return:{COLOR_RESET}")
        sel = prompt_input("SELECT REPORT > ").strip()

        if sel.lower() in ("b", "back", "q", "exit", ""):
            return

        if sel.isdigit():
            idx = int(sel) - 1
            if 0 <= idx < len(history):
                _export_scan_report(history[idx])
