"""
NayVista Shield - Security Posture View
Renders the security posture summary box, audit metrics, and category breakdown.
"""

from typing import Dict, Any, List
from scanner.cli.theme import (
    COLOR_BRAND_YELLOW, COLOR_WHITE, COLOR_MUTED_GRAY, COLOR_GREEN, COLOR_RED, COLOR_ORANGE, COLOR_RESET, colorize,
    BOX_DOUBLE_TOP, BOX_DOUBLE_TR, BOX_DOUBLE_BL, BOX_DOUBLE_BR, BOX_DOUBLE_H, BOX_DOUBLE_V,
    PROGRESS_FULL, PROGRESS_EMPTY, CAN_UTF8
)
from scanner.cli.terminal import get_terminal_width, strip_ansi

def _format_double_box_row(content: str, width: int = 60) -> str:
    """Formats a row with double borders."""
    inner_width = width - 4
    visible_len = len(strip_ansi(content))
    pad = max(0, inner_width - visible_len)
    side = colorize(BOX_DOUBLE_V, COLOR_BRAND_YELLOW)
    return f"{side} {content}{' ' * pad} {side}"

def render_security_posture(result: Dict[str, Any], width: int = 60) -> None:
    """Renders the executive security posture card."""
    scoring = result.get("scoring", {})
    score = scoring.get("score")
    grade = scoring.get("grade", "A") if score is not None else "N/A"
    risk = scoring.get("risk_level", "LOW") if score is not None else "LIMITED"
    posture = result.get("posture", "ASSESSED")
    counts = scoring.get("counts", {})
    duration = result.get("duration_seconds", 0.0)
    pages_scanned = result.get("pages_scanned", 0)
    findings = result.get("findings", [])
    coverage = result.get("coverage", {})
    cov_pct = coverage.get("percentage", 100 if posture != "LIMITED" else 36)
    completed_stages = coverage.get("completed_stages", 14 if posture != "LIMITED" else 5)
    limitations = result.get("limitations", [])

    c_crit = counts.get("CRITICAL", 0)
    c_high = counts.get("HIGH", 0)
    c_med = counts.get("MEDIUM", 0)
    c_low = counts.get("LOW", 0)
    c_info = counts.get("INFO", 0)

    # Header and Top
    top_line = f"{BOX_DOUBLE_TOP}{BOX_DOUBLE_H * (width - 2)}{BOX_DOUBLE_TR}"
    bottom_line = f"{BOX_DOUBLE_BL}{BOX_DOUBLE_H * (width - 2)}{BOX_DOUBLE_BR}"

    print()
    print(colorize(top_line, COLOR_BRAND_YELLOW))
    print(_format_double_box_row("", width))

    card_title = "ASSESSMENT LIMITED" if posture == "LIMITED" else "SECURITY POSTURE"
    title = colorize(card_title, COLOR_BRAND_YELLOW)
    pad_title = max(0, (width - 4 - len(card_title)) // 2)
    print(_format_double_box_row(f"{' ' * pad_title}{title}", width))
    print(_format_double_box_row("", width))

    # Score or Coverage line
    if score is None or posture == "LIMITED":
        score_text = "SCORE: N/A"
        pad_score = max(0, (width - 4 - len(score_text)) // 2)
        print(_format_double_box_row(f"{' ' * pad_score}{colorize(score_text, COLOR_BRAND_YELLOW)}", width))

        cov_text = f"COVERAGE: {completed_stages}/14 STAGES ({cov_pct}%)"
        pad_cov = max(0, (width - 4 - len(cov_text)) // 2)
        print(_format_double_box_row(f"{' ' * pad_cov}{colorize(cov_text, COLOR_WHITE)}", width))
    else:
        score_text = f"{score} / 100"
        pad_score = max(0, (width - 4 - len(score_text)) // 2)
        print(_format_double_box_row(f"{' ' * pad_score}{colorize(score_text, COLOR_BRAND_YELLOW)}", width))

    # Grade line
    grade_text = f"GRADE {grade}"
    pad_grade = max(0, (width - 4 - len(grade_text)) // 2)
    grade_color = COLOR_GREEN if grade in ("A", "B") else (COLOR_BRAND_YELLOW if grade == "C" else (COLOR_MUTED_GRAY if grade == "N/A" else COLOR_RED))
    print(_format_double_box_row(f"{' ' * pad_grade}{colorize(grade_text, grade_color)}", width))

    # Risk line
    risk_color = COLOR_RED if risk in ("CRITICAL", "HIGH") else (COLOR_BRAND_YELLOW if risk in ("MEDIUM", "LIMITED") else COLOR_GREEN)
    pad_risk = max(0, (width - 4 - len(risk)) // 2)
    print(_format_double_box_row(f"{' ' * pad_risk}{colorize(risk, risk_color)}", width))
    print(_format_double_box_row("", width))

    # Counts line
    c_line = (
        f"{COLOR_RED}CRITICAL  {c_crit}{COLOR_RESET}      "
        f"{COLOR_ORANGE}HIGH  {c_high}{COLOR_RESET}      "
        f"{COLOR_BRAND_YELLOW}MEDIUM  {c_med}{COLOR_RESET}"
    )
    pad_c = max(0, (width - 4 - len(f"CRITICAL  {c_crit}      HIGH  {c_high}      MEDIUM  {c_med}")) // 2)
    print(_format_double_box_row(f"{' ' * pad_c}{c_line}", width))

    low_line = f"{COLOR_GREEN}LOW       {c_low}{COLOR_RESET}      {COLOR_MUTED_GRAY}INFO  {c_info}{COLOR_RESET}"
    pad_low = max(0, (width - 4 - len(f"LOW       {c_low}      INFO  {c_info}")) // 2)
    print(_format_double_box_row(f"{' ' * pad_low}{low_line}", width))
    print(_format_double_box_row("", width))

    # Metrics
    metrics_str = f"PAGES AUDITED  {pages_scanned}       DURATION  {duration}s"
    pad_m = max(0, (width - 4 - len(metrics_str)) // 2)
    print(_format_double_box_row(f"{' ' * pad_m}{COLOR_WHITE}{metrics_str}{COLOR_RESET}", width))

    print(colorize(bottom_line, COLOR_BRAND_YELLOW))
    print()

    # Detailed summary
    summary_status = "COMPLETED WITH LIMITATIONS" if posture == "LIMITED" else "ASSESSMENT COMPLETE"
    print(f"{COLOR_BRAND_YELLOW}{summary_status}{COLOR_RESET}")
    print()
    print(f"  {COLOR_MUTED_GRAY}TARGET   {COLOR_RESET} {COLOR_WHITE}{result.get('target')}{COLOR_RESET}")
    print(f"  {COLOR_MUTED_GRAY}MODE     {COLOR_RESET} {COLOR_WHITE}{result.get('mode', 'DEFENSIVE / SAFE')}{COLOR_RESET}")
    print(f"  {COLOR_MUTED_GRAY}IP ADDR  {COLOR_RESET} {COLOR_WHITE}{result.get('resolved_ip', 'N/A')}{COLOR_RESET}")
    if posture == "LIMITED":
        print(f"  {COLOR_MUTED_GRAY}SCORE    {COLOR_RESET} {COLOR_BRAND_YELLOW}N/A{COLOR_RESET} {COLOR_MUTED_GRAY}(Insufficient evidence){COLOR_RESET}")
        print(f"  {COLOR_MUTED_GRAY}COVERAGE {COLOR_RESET} {COLOR_WHITE}{cov_pct}% ({completed_stages}/14 stages){COLOR_RESET}")
    else:
        print(f"  {COLOR_MUTED_GRAY}SCORE    {COLOR_RESET} {COLOR_BRAND_YELLOW}{score} / 100{COLOR_RESET}")
    print(f"  {COLOR_MUTED_GRAY}GRADE    {COLOR_RESET} {colorize(grade, grade_color)}")
    print(f"  {COLOR_MUTED_GRAY}RISK     {COLOR_RESET} {colorize(risk, risk_color)}")
    print(f"  {COLOR_MUTED_GRAY}POSTURE  {COLOR_RESET} {COLOR_WHITE}{posture}{COLOR_RESET}")
    print(f"  {COLOR_MUTED_GRAY}FINDINGS {COLOR_RESET} {COLOR_WHITE}{len(findings)}{COLOR_RESET}")
    print()

    # If limitations recorded, display them cleanly
    if limitations:
        print(f"{COLOR_BRAND_YELLOW}ASSESSMENT LIMITATIONS{COLOR_RESET}")
        print(f"  {COLOR_MUTED_GRAY}Note: Target reachability limitations do not indicate a vulnerability or API failure.{COLOR_RESET}")
        print()
        for lim in limitations:
            stg = lim.get("stage", "Stage")
            rsn = lim.get("reason", "")
            print(f"  {COLOR_BRAND_YELLOW}• {stg}{COLOR_RESET}: {COLOR_WHITE}{rsn}{COLOR_RESET}")
        print()

    # Network Service Exposure
    render_network_exposure(result.get("network_exposure", []))

    # Category Breakdown
    render_category_breakdown(findings)

def render_network_exposure(network_exposure: List[Dict[str, Any]]):
    """Renders the curated network service exposure table."""
    if not network_exposure:
        return

    print(f"{COLOR_BRAND_YELLOW}NETWORK SERVICE EXPOSURE{COLOR_RESET}")
    print()
    print(f"  {COLOR_MUTED_GRAY}{'PORT':<10}{'SERVICE':<16}{'STATE':<12}{'EXPOSURE':<12}{'RISK':<10}{COLOR_RESET}")
    print(f"  {COLOR_MUTED_GRAY}{'─' * 58}{COLOR_RESET}")

    for entry in network_exposure:
        port_str = f"TCP/{entry.get('port')}"
        srv_str = entry.get("service", "-")
        state = entry.get("state", "CLOSED")
        exposure = entry.get("exposure", "-")
        risk = entry.get("risk", "-")

        if state == "OPEN":
            state_colored = f"{COLOR_GREEN}OPEN{COLOR_RESET}"
        elif state == "FILTERED":
            state_colored = f"{COLOR_MUTED_GRAY}FILTERED{COLOR_RESET}"
        else:
            state_colored = f"{COLOR_MUTED_GRAY}CLOSED{COLOR_RESET}"

        if risk == "HIGH":
            risk_colored = f"{COLOR_RED}HIGH{COLOR_RESET}"
        elif risk == "REVIEW":
            risk_colored = f"{COLOR_ORANGE}REVIEW{COLOR_RESET}"
        elif risk == "EXPECTED":
            risk_colored = f"{COLOR_GREEN}EXPECTED{COLOR_RESET}"
        else:
            risk_colored = f"{COLOR_MUTED_GRAY}-{COLOR_RESET}"

        print(f"  {COLOR_WHITE}{port_str:<10}{srv_str:<16}{COLOR_RESET}{state_colored:<21}{exposure:<12}{risk_colored}")
    print()

def render_category_breakdown(findings: List[Dict[str, Any]]):
    """Calculates and renders category defense posture bars."""
    categories = ["HEADERS", "COOKIES", "TLS", "CORS", "REDIRECTS", "CONTENT"]
    cat_penalties = {cat: 0 for cat in categories}

    for f in findings:
        cat = (f.get("category") or "").upper()
        sev = (f.get("severity") or "INFO").upper()
        penalty = 30 if sev == "CRITICAL" else (20 if sev == "HIGH" else (10 if sev == "MEDIUM" else 5))
        for known in categories:
            if known in cat or cat in known:
                cat_penalties[known] += penalty

    print(f"{COLOR_BRAND_YELLOW}SECURITY BREAKDOWN{COLOR_RESET}")
    print()
    for cat in categories:
        score_val = max(0, 100 - cat_penalties[cat])
        filled = int((score_val / 100) * 10)
        bar = (PROGRESS_FULL * filled) + (PROGRESS_EMPTY * (10 - filled))
        bar_color = COLOR_GREEN if score_val >= 80 else (COLOR_BRAND_YELLOW if score_val >= 50 else COLOR_RED)
        print(f"  {COLOR_MUTED_GRAY}{cat:<12}{COLOR_RESET} {bar_color}{bar}{COLOR_RESET}  {COLOR_WHITE}{score_val:>3}%{COLOR_RESET}")
    print()
