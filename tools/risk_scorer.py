"""Weighted risk scoring formula.

Combines findings from all scanning tools into a single 0–100 risk score.

Formula:
    raw = crit × 30 + high × 15 + med × 5 + low × 1
          + dep_crit × 25 + dep_high × 12
          + files_changed × 0.5
    score = min(100, int(raw))

Labels:
    < 40  → LOW
    40–69 → MEDIUM
    ≥ 70  → HIGH
"""

from __future__ import annotations

from shared.models import Finding, RiskScore, ScanResult
from shared.verdict import Severity


def compute_risk_score(
    all_findings: list[Finding],
    dep_findings: list[Finding],
    files_changed: int = 0,
) -> RiskScore:
    """Compute a weighted risk score from scan results.

    Args:
        all_findings: All findings from static + security scanners.
        dep_findings: Findings specifically from dependency audit (pip-audit).
        files_changed: Number of files modified in this PR.

    Returns:
        A RiskScore with score, label, and detailed breakdown.
    """
    # Count code findings by severity
    crit = sum(1 for f in all_findings if f.severity == Severity.CRITICAL)
    high = sum(1 for f in all_findings if f.severity == Severity.HIGH)
    med = sum(1 for f in all_findings if f.severity == Severity.MEDIUM)
    low = sum(1 for f in all_findings if f.severity == Severity.LOW)

    # Count dep findings separately (weighted differently)
    dep_crit = sum(1 for f in dep_findings if f.severity == Severity.CRITICAL)
    dep_high = sum(1 for f in dep_findings if f.severity == Severity.HIGH)

    # Weighted formula
    code_score = crit * 30 + high * 15 + med * 5 + low * 1
    dep_score = dep_crit * 25 + dep_high * 12
    churn_score = files_changed * 0.5

    raw = code_score + dep_score + churn_score
    score = min(100, int(raw))

    # Label
    if score < 40:
        label = "LOW"
    elif score < 70:
        label = "MEDIUM"
    else:
        label = "HIGH"

    breakdown = {
        "critical_findings": crit,
        "high_findings": high,
        "medium_findings": med,
        "low_findings": low,
        "critical_dep_cves": dep_crit,
        "high_dep_cves": dep_high,
        "files_changed": files_changed,
        "code_score": code_score,
        "dep_score": dep_score,
        "churn_score": churn_score,
        "raw_total": raw,
    }

    return RiskScore(score=score, label=label, breakdown=breakdown)


def aggregate_findings_from_results(scan_results: list[ScanResult]) -> list[Finding]:
    """Flatten all findings from a list of ScanResult objects."""
    findings: list[Finding] = []
    for result in scan_results:
        findings.extend(result.findings)
    return findings
