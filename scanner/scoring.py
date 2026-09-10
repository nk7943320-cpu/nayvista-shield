"""
SentinelScan - Risk & Security Score Calculator
Calculates numeric security score (0-100), letter grade (A-F), and overall risk level.
"""

from typing import List, Dict, Any

SEVERITY_DEDUCTIONS = {
    "CRITICAL": 25.0,
    "HIGH": 15.0,
    "MEDIUM": 8.0,
    "LOW": 3.0,
    "INFO": 0.0,
}

CONFIDENCE_WEIGHTS = {
    "HIGH": 1.0,
    "MEDIUM": 0.85,
    "LOW": 0.60,
}

def calculate_security_score(findings: List[Dict[str, Any]], posture: str = "ASSESSED", coverage: Optional[int] = None) -> Dict[str, Any]:
    """
    Computes overall score, severity counts, grade, posture, and risk rating.
    When posture == "LIMITED", score is set to None (N/A) with explicit reason,
    strictly distinguishing Assessment Coverage from Security Score.
    """
    counts = {
        "CRITICAL": 0,
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0,
        "INFO": 0,
    }

    for f in findings:
        sev = f.get("severity", "INFO").upper()
        conf = f.get("confidence", "MEDIUM").upper()

        if sev in counts:
            counts[sev] += 1

    # If assessment was limited due to target reachability, do not calculate a misleading score
    if posture == "LIMITED":
        return {
            "score": None,
            "grade": "N/A",
            "risk_level": "LIMITED",
            "posture": "LIMITED",
            "coverage": coverage if coverage is not None else 0,
            "reason": "Insufficient evidence for a meaningful security posture score.",
            "total_findings": len(findings),
            "counts": counts,
        }

    total_deduction = 0.0
    for f in findings:
        sev = f.get("severity", "INFO").upper()
        conf = f.get("confidence", "MEDIUM").upper()
        base_deduction = SEVERITY_DEDUCTIONS.get(sev, 0.0)
        weight = CONFIDENCE_WEIGHTS.get(conf, 0.85)
        total_deduction += base_deduction * weight

    # Base score 100, clamped 0 - 100
    raw_score = 100.0 - total_deduction
    score = max(0, min(100, int(round(raw_score))))

    # Adjust score and grade based on posture (e.g. WAF/403, 429 rate limiting, or 5xx server errors)
    if posture == "RESTRICTED":
        # Target actively blocked inspection or rate limited.
        # Cap at 70 (Grade C) and ensure minimum risk is at least MEDIUM.
        score = min(score, 70)
    elif posture == "DEGRADED":
        # Target returned 5xx server errors or failed TLS validation.
        # Cap at 65 (Grade D) and ensure minimum risk is at least MEDIUM.
        score = min(score, 65)

    # Letter Grade
    if score >= 90:
        grade = "A"
    elif score >= 80:
        grade = "B"
    elif score >= 70:
        grade = "C"
    elif score >= 60:
        grade = "D"
    else:
        grade = "F"

    # Risk level classification: strictly LOW, MEDIUM, HIGH, CRITICAL
    if counts["CRITICAL"] > 0:
        risk_level = "CRITICAL"
    elif counts["HIGH"] > 0 or score < 60:
        risk_level = "HIGH"
    elif counts["MEDIUM"] > 0 or score < 80 or posture in ("RESTRICTED", "DEGRADED"):
        risk_level = "MEDIUM"
    else:
        risk_level = "LOW"

    return {
        "score": score,
        "grade": grade,
        "risk_level": risk_level,
        "posture": posture,
        "coverage": coverage if coverage is not None else 100,
        "total_findings": len(findings),
        "counts": counts,
    }
