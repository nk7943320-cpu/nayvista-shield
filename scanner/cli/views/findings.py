"""
NayVista Shield - Findings Browser & Detail View
Provides a clean, readable card-based finding list and in-depth vulnerability inspector.
Enforces evidence sanitization and responsive wrapping.
"""

from typing import List, Dict, Any, Optional
from scanner.cli.theme import (
    COLOR_BRAND_YELLOW, COLOR_WHITE, COLOR_MUTED_GRAY, COLOR_RESET, colorize, format_severity,
    BOX_DIVIDER_LEFT, BOX_DIVIDER_RIGHT, BOX_HORIZ, BOX_VERT
)
from scanner.cli.terminal import (
    clear_screen, get_terminal_width, make_box_top, make_box_bottom,
    format_box_row, make_box_divider, wrap_text_lines, prompt_input, prompt_choice
)

def render_findings_list(findings: List[Dict[str, Any]], page: int = 0, page_size: int = 8) -> None:
    """Renders a paginated list of findings formatted as numbered cards."""
    total = len(findings)
    if total == 0:
        print(f"  {COLOR_BRAND_YELLOW}[OK] Zero vulnerabilities or misconfigurations discovered!{COLOR_RESET}")
        print()
        return

    start = page * page_size
    end = min(start + page_size, total)

    print(f"{COLOR_BRAND_YELLOW}FINDINGS [{total}]{COLOR_RESET}  {COLOR_MUTED_GRAY}(Showing {start + 1} - {end} of {total}){COLOR_RESET}")
    print()

    for idx in range(start, end):
        f = findings[idx]
        num_str = f"{idx + 1:02d}"
        sev_str = format_severity(f.get("severity", "INFO"))
        title = f.get("title", "Untitled Finding")
        owasp = f.get("owasp", "OWASP Unmapped")
        cwe = f.get("cwe", "")
        conf = f.get("confidence", "FIRM")
        cwe_str = f" • {cwe}" if cwe else ""

        print(f"  {COLOR_BRAND_YELLOW}{num_str}{COLOR_RESET}  {sev_str}")
        print(f"      {COLOR_WHITE}{title}{COLOR_RESET}")
        print(f"      {COLOR_MUTED_GRAY}{owasp}{cwe_str} • CONFIDENCE {conf}{COLOR_RESET}")
        print()

def render_finding_detail(f: Dict[str, Any], idx: int, total: int, width: int = 68) -> None:
    """Renders detailed finding view with sanitized observation, impact, and remediation."""
    clear_screen()
    width = min(width, get_terminal_width())
    sev_str = format_severity(f.get("severity", "INFO"))
    title = f.get("title", "Untitled Finding")
    owasp = f.get("owasp", "Unmapped")
    cwe = f.get("cwe", "N/A")
    conf = f.get("confidence", "FIRM")
    url = f.get("url", "Target origin")
    component = f.get("affected_component", "Server Response")
    desc = f.get("description", "")
    evidence = f.get("evidence", "No evidence recorded.")
    impact = f.get("impact", "Potential security weakness.")
    remediation = f.get("remediation", "Apply vendor security best practices.")
    references = f.get("references", [])

    print()
    print(make_box_top(width))

    header_line = f"#{idx + 1:02d}  {sev_str}  {COLOR_WHITE}{title}{COLOR_RESET}"
    for line in wrap_text_lines(header_line, width - 4):
        print(format_box_row(line, width))

    print(make_box_divider(width))
    print(format_box_row("", width))

    print(format_box_row(f"{COLOR_MUTED_GRAY}OWASP       {COLOR_RESET}{COLOR_WHITE}{owasp}{COLOR_RESET}", width))
    print(format_box_row(f"{COLOR_MUTED_GRAY}CWE         {COLOR_RESET}{COLOR_WHITE}{cwe}{COLOR_RESET}", width))
    print(format_box_row(f"{COLOR_MUTED_GRAY}CONFIDENCE  {COLOR_RESET}{COLOR_WHITE}{conf}{COLOR_RESET}", width))
    print(format_box_row(f"{COLOR_MUTED_GRAY}TARGET      {COLOR_RESET}{COLOR_WHITE}{url[:width-18]}{COLOR_RESET}", width))
    print(format_box_row(f"{COLOR_MUTED_GRAY}COMPONENT   {COLOR_RESET}{COLOR_WHITE}{component[:width-18]}{COLOR_RESET}", width))
    print(format_box_row("", width))

    # Observation
    print(format_box_row(f"{COLOR_BRAND_YELLOW}OBSERVATION{COLOR_RESET}", width))
    for line in wrap_text_lines(desc, width - 6):
        print(format_box_row(f"  {COLOR_WHITE}{line}{COLOR_RESET}", width))
    if evidence:
        for line in wrap_text_lines(f"Evidence: {evidence}", width - 6):
            print(format_box_row(f"  {COLOR_MUTED_GRAY}{line}{COLOR_RESET}", width))
    print(format_box_row("", width))

    # Impact
    print(format_box_row(f"{COLOR_BRAND_YELLOW}IMPACT{COLOR_RESET}", width))
    for line in wrap_text_lines(impact, width - 6):
        print(format_box_row(f"  {COLOR_WHITE}{line}{COLOR_RESET}", width))
    print(format_box_row("", width))

    # Remediation
    print(format_box_row(f"{COLOR_BRAND_YELLOW}REMEDIATION{COLOR_RESET}", width))
    for line in wrap_text_lines(remediation, width - 6):
        print(format_box_row(f"  {COLOR_WHITE}{line}{COLOR_RESET}", width))
    print(format_box_row("", width))

    # References
    if references:
        print(format_box_row(f"{COLOR_BRAND_YELLOW}REFERENCES{COLOR_RESET}", width))
        for ref in references[:3]:
            print(format_box_row(f"  {COLOR_MUTED_GRAY}• {ref[:width-8]}{COLOR_RESET}", width))
        print(format_box_row("", width))

    print(make_box_bottom(width))
    print()

def browse_findings(findings: List[Dict[str, Any]]) -> None:
    """Interactive findings browsing loop with pagination and detail drilldown."""
    if not findings:
        print(f"  {COLOR_BRAND_YELLOW}Zero findings to review.{COLOR_RESET}")
        return

    page = 0
    page_size = 6
    total = len(findings)
    max_pages = (total + page_size - 1) // page_size

    while True:
        clear_screen()
        render_findings_list(findings, page=page, page_size=page_size)

        print(f"  {COLOR_MUTED_GRAY}Navigation:{COLOR_RESET}")
        print(f"  {COLOR_BRAND_YELLOW}[1-N]{COLOR_RESET} {COLOR_WHITE}VIEW FINDING # (e.g. 1){COLOR_RESET}")
        if page < max_pages - 1:
            print(f"  {COLOR_BRAND_YELLOW}[N]{COLOR_RESET}   {COLOR_WHITE}NEXT PAGE{COLOR_RESET}")
        if page > 0:
            print(f"  {COLOR_BRAND_YELLOW}[P]{COLOR_RESET}   {COLOR_WHITE}PREVIOUS PAGE{COLOR_RESET}")
        print(f"  {COLOR_BRAND_YELLOW}[B]{COLOR_RESET}   {COLOR_MUTED_GRAY}BACK TO MENU{COLOR_RESET}")
        print()

        choice = prompt_input("NAYVISTA-SHIELD > ").strip().lower()
        if choice in ("b", "back", "exit", "q"):
            break
        elif choice in ("n", "next") and page < max_pages - 1:
            page += 1
        elif choice in ("p", "prev", "previous") and page > 0:
            page -= 1
        elif choice.isdigit():
            idx = int(choice) - 1
            if 0 <= idx < total:
                _inspect_finding_loop(findings, idx)
            else:
                print(f"  {COLOR_MUTED_GRAY}Invalid finding number (1-{total}){COLOR_RESET}")

def _inspect_finding_loop(findings: List[Dict[str, Any]], current_idx: int) -> None:
    """Sub-loop allowing navigation between individual findings (next/prev/back)."""
    idx = current_idx
    total = len(findings)

    while True:
        render_finding_detail(findings[idx], idx, total)
        print(f"  {COLOR_MUTED_GRAY}Options:{COLOR_RESET}")
        if idx + 1 < total:
            print(f"  {COLOR_BRAND_YELLOW}[N]{COLOR_RESET} {COLOR_WHITE}NEXT FINDING (#{idx + 2:02d}){COLOR_RESET}")
        if idx > 0:
            print(f"  {COLOR_BRAND_YELLOW}[P]{COLOR_RESET} {COLOR_WHITE}PREVIOUS FINDING (#{idx:02d}){COLOR_RESET}")
        print(f"  {COLOR_BRAND_YELLOW}[B]{COLOR_RESET} {COLOR_MUTED_GRAY}BACK TO LIST{COLOR_RESET}")
        print()

        choice = prompt_input("NAYVISTA-SHIELD > ").strip().lower()
        if choice in ("b", "back", "q"):
            break
        elif choice in ("n", "next") and idx + 1 < total:
            idx += 1
        elif choice in ("p", "prev") and idx > 0:
            idx -= 1
