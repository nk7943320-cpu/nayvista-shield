"""
NayVista Shield - Scan History & Target History Views
Renders historical assessment archives and grouped target origin timelines.
Supports inspection, comparison, and report generation from history.
"""

from typing import List, Dict, Any, Optional
from scanner.cli.theme import (
    COLOR_BRAND_YELLOW, COLOR_WHITE, COLOR_MUTED_GRAY, COLOR_RESET, colorize, format_severity
)
from scanner.cli.terminal import (
    clear_screen, prompt_input, prompt_choice, get_terminal_width
)
from scanner.cli.history import (
    load_history, get_scan, get_targets_history, delete_scan
)
from scanner.cli.views.posture import render_security_posture
from scanner.cli.views.findings import browse_findings

def render_scan_history_menu() -> None:
    """Displays scan history with numbered selection and inspection options."""
    while True:
        clear_screen()
        history = load_history()
        print()
        print(f"{COLOR_BRAND_YELLOW}SCAN HISTORY{COLOR_RESET}")
        print()

        if not history:
            print(f"  {COLOR_MUTED_GRAY}NO PREVIOUS ASSESSMENTS FOUND{COLOR_RESET}")
            print()
            prompt_input("Press Enter to return > ")
            return

        # Render list of scans
        for idx, scan in enumerate(history[:20]):
            num_str = f"[{idx + 1:02d}]"
            hostname = scan.get("hostname", "unknown")[:24]
            score_str = f"{scan.get('score', 100):>3}/100"
            risk = scan.get("risk_level", "LOW")
            risk_badge = format_severity(risk)
            date_str = (scan.get("created_at") or "")[:10]
            print(f"  {COLOR_BRAND_YELLOW}{num_str}{COLOR_RESET}  {COLOR_WHITE}{hostname:<24}{COLOR_RESET}  {COLOR_BRAND_YELLOW}{score_str}{COLOR_RESET}  {risk_badge:<16}  {COLOR_MUTED_GRAY}{date_str}{COLOR_RESET}")

        print()
        print(f"  {COLOR_MUTED_GRAY}Enter scan number (1-{min(len(history), 20)}) or B to return:{COLOR_RESET}")
        sel = prompt_input("SELECT SCAN > ").strip()

        if sel.lower() in ("b", "back", "q", "exit", ""):
            return

        if sel.isdigit():
            idx = int(sel) - 1
            if 0 <= idx < len(history):
                _handle_selected_scan(history[idx])

def _handle_selected_scan(scan: Dict[str, Any]) -> None:
    """Provides actions on a selected scan: Inspect, Report, Compare, Delete, Back."""
    while True:
        clear_screen()
        hostname = scan.get("hostname", "target")
        print()
        print(f"{COLOR_BRAND_YELLOW}SCAN RECORD :: {hostname}{COLOR_RESET}")
        print()
        print(f"  {COLOR_MUTED_GRAY}Target    :{COLOR_RESET} {COLOR_WHITE}{scan.get('target')}{COLOR_RESET}")
        print(f"  {COLOR_MUTED_GRAY}Date      :{COLOR_RESET} {COLOR_WHITE}{scan.get('created_at')}{COLOR_RESET}")
        print(f"  {COLOR_MUTED_GRAY}Score     :{COLOR_RESET} {COLOR_BRAND_YELLOW}{scan.get('score')}/100 (Grade {scan.get('grade')}){COLOR_RESET}")
        print(f"  {COLOR_MUTED_GRAY}Risk      :{COLOR_RESET} {format_severity(scan.get('risk_level', 'LOW'))}")
        print(f"  {COLOR_MUTED_GRAY}Findings  :{COLOR_RESET} {COLOR_WHITE}{scan.get('findings_count', 0)}{COLOR_RESET}")
        print(f"  {COLOR_MUTED_GRAY}Posture   :{COLOR_RESET} {COLOR_WHITE}{scan.get('posture', 'ASSESSED')}{COLOR_RESET}")
        print()
        print(f"  {COLOR_BRAND_YELLOW}[1]{COLOR_RESET} {COLOR_WHITE}INSPECT (VIEW FINDINGS & POSTURE){COLOR_RESET}")
        print(f"  {COLOR_BRAND_YELLOW}[2]{COLOR_RESET} {COLOR_WHITE}EXPORT HTML / JSON REPORT{COLOR_RESET}")
        print(f"  {COLOR_BRAND_YELLOW}[3]{COLOR_RESET} {COLOR_WHITE}COMPARE WITH ANOTHER SCAN{COLOR_RESET}")
        print(f"  {COLOR_BRAND_YELLOW}[4]{COLOR_RESET} {COLOR_MUTED_GRAY}BACK TO HISTORY{COLOR_RESET}")
        print()

        choice = prompt_choice({"1", "2", "3", "4", "b"}, prompt_label="NAYVISTA-SHIELD > ", default="1")
        if choice in ("4", "b"):
            return
        elif choice == "1":
            _inspect_scan(scan)
        elif choice == "2":
            _export_scan_report(scan)
        elif choice == "3":
            _compare_scans(scan)

def _inspect_scan(scan: Dict[str, Any]) -> None:
    """Displays posture and findings for a historical scan."""
    clear_screen()
    render_security_posture(scan)
    findings = scan.get("findings", [])
    print(f"  {COLOR_BRAND_YELLOW}[1]{COLOR_RESET} {COLOR_WHITE}BROWSE FINDINGS ({len(findings)}){COLOR_RESET}")
    print(f"  {COLOR_BRAND_YELLOW}[2]{COLOR_RESET} {COLOR_MUTED_GRAY}BACK{COLOR_RESET}")
    print()
    ch = prompt_choice({"1", "2"}, prompt_label="NAYVISTA-SHIELD > ", default="1")
    if ch == "1":
        browse_findings(findings)

def _export_scan_report(scan: Dict[str, Any]) -> None:
    """Generates an HTML or JSON report file from a historical scan record."""
    from scanner.report import generate_html_report, generate_json_report
    clear_screen()
    print()
    print(f"{COLOR_BRAND_YELLOW}EXPORT REPORT{COLOR_RESET}")
    print()
    print(f"  {COLOR_BRAND_YELLOW}[1]{COLOR_RESET} {COLOR_WHITE}SAVE HTML AUDIT REPORT{COLOR_RESET}")
    print(f"  {COLOR_BRAND_YELLOW}[2]{COLOR_RESET} {COLOR_WHITE}SAVE JSON AUDIT REPORT{COLOR_RESET}")
    print(f"  {COLOR_BRAND_YELLOW}[3]{COLOR_RESET} {COLOR_MUTED_GRAY}BACK{COLOR_RESET}")
    print()
    ch = prompt_choice({"1", "2", "3"}, prompt_label="NAYVISTA-SHIELD > ", default="1")
    if ch == "1":
        default_name = f"nayvista_report_{scan.get('hostname')}_{int(scan.get('timestamp', 0))}.html"
        filename = prompt_input(f"Output file [{default_name}] > ").strip() or default_name
        try:
            html = generate_html_report(scan)
            with open(filename, "w", encoding="utf-8") as f:
                f.write(html)
            print(f"  {COLOR_BRAND_YELLOW}[OK] HTML report saved to: {filename}{COLOR_RESET}")
        except Exception as e:
            print(f"  Error generating report: {e}")
        prompt_input("Press Enter to continue > ")
    elif ch == "2":
        default_name = f"nayvista_report_{scan.get('hostname')}_{int(scan.get('timestamp', 0))}.json"
        filename = prompt_input(f"Output file [{default_name}] > ").strip() or default_name
        try:
            js = generate_json_report(scan)
            with open(filename, "w", encoding="utf-8") as f:
                f.write(js)
            print(f"  {COLOR_BRAND_YELLOW}[OK] JSON report saved to: {filename}{COLOR_RESET}")
        except Exception as e:
            print(f"  Error generating report: {e}")
        prompt_input("Press Enter to continue > ")

def _compare_scans(base_scan: Dict[str, Any]) -> None:
    """Compares the selected scan against another scan of the same target origin."""
    history = load_history()
    target_origin = base_scan.get("origin")
    matching = [s for s in history if s.get("origin") == target_origin and s.get("id") != base_scan.get("id")]

    clear_screen()
    print()
    print(f"{COLOR_BRAND_YELLOW}COMPARE SCANS :: {target_origin}{COLOR_RESET}")
    print()

    if not matching:
        print(f"  {COLOR_MUTED_GRAY}No other scans found for origin {target_origin} to compare against.{COLOR_RESET}")
        print()
        prompt_input("Press Enter to return > ")
        return

    for idx, s in enumerate(matching[:10]):
        print(f"  {COLOR_BRAND_YELLOW}[{idx + 1:02d}]{COLOR_RESET} {COLOR_WHITE}{s.get('created_at')}{COLOR_RESET} — Score: {s.get('score')}/100, Risk: {s.get('risk_level')}")

    print()
    sel = prompt_input("Select scan to compare against (1-N) or B to cancel > ").strip()
    if sel.isdigit() and 1 <= int(sel) <= len(matching):
        target_scan = matching[int(sel) - 1]
        _render_comparison_summary(base_scan, target_scan)

def _render_comparison_summary(base: Dict[str, Any], target: Dict[str, Any]) -> None:
    """Renders side-by-side comparison metrics between two scans."""
    clear_screen()
    print()
    print(f"{COLOR_BRAND_YELLOW}AUDIT COMPARISON DIFF{COLOR_RESET}")
    print()
    print(f"  {COLOR_MUTED_GRAY}BASELINE :{COLOR_RESET} {base.get('created_at')} (Score: {base.get('score')}/100, Grade: {base.get('grade')})")
    print(f"  {COLOR_MUTED_GRAY}TARGET   :{COLOR_RESET} {target.get('created_at')} (Score: {target.get('score')}/100, Grade: {target.get('grade')})")
    print()

    score_diff = target.get("score", 100) - base.get("score", 100)
    diff_sign = "+" if score_diff > 0 else ""
    diff_color = COLOR_BRAND_YELLOW if score_diff >= 0 else COLOR_MUTED_GRAY
    print(f"  {COLOR_MUTED_GRAY}SCORE DELTA   :{COLOR_RESET} {diff_color}{diff_sign}{score_diff}{COLOR_RESET}")
    print(f"  {COLOR_MUTED_GRAY}POSTURE DELTA :{COLOR_RESET} {base.get('posture')} -> {target.get('posture')}")

    # Finding diffs
    base_ids = {f.get("id") for f in base.get("findings", [])}
    target_ids = {f.get("id") for f in target.get("findings", [])}

    new_ids = target_ids - base_ids
    resolved_ids = base_ids - target_ids
    persistent_ids = base_ids & target_ids

    print()
    print(f"  {COLOR_BRAND_YELLOW}+ NEW FINDINGS        :{COLOR_RESET} {len(new_ids)}")
    print(f"  {COLOR_BRAND_YELLOW}- RESOLVED FINDINGS   :{COLOR_RESET} {len(resolved_ids)}")
    print(f"  {COLOR_MUTED_GRAY}= PERSISTENT FINDINGS :{COLOR_RESET} {len(persistent_ids)}")
    print()

    prompt_input("Press Enter to return > ")

def render_target_history_menu() -> None:
    """Renders scans grouped by normalized target origin showing score/risk progression."""
    clear_screen()
    groups = get_targets_history()
    print()
    print(f"{COLOR_BRAND_YELLOW}TARGET HISTORY{COLOR_RESET}")
    print()

    if not groups:
        print(f"  {COLOR_MUTED_GRAY}NO PREVIOUS ASSESSMENTS FOUND{COLOR_RESET}")
        print()
        prompt_input("Press Enter to return > ")
        return

    for origin, scans in groups.items():
        print(f"  {COLOR_WHITE}{origin}{COLOR_RESET}")
        for idx, scan in enumerate(scans[:5]):
            score_str = f"{scan.get('score', 100):>3}/100"
            risk = scan.get("risk_level", "LOW")
            risk_badge = format_severity(risk)
            date_str = (scan.get("created_at") or "")[:16]
            posture = scan.get("posture", "ASSESSED")
            print(f"    {COLOR_BRAND_YELLOW}[{idx + 1:02d}]{COLOR_RESET} {COLOR_BRAND_YELLOW}{score_str}{COLOR_RESET}   {risk_badge:<14}  {COLOR_MUTED_GRAY}{date_str}   {posture}{COLOR_RESET}")
        print()

    prompt_input("Press Enter to return > ")
