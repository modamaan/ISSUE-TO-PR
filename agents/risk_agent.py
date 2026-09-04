"""Agent ➏: RiskAgent

Aggregates all findings from ScanAgent, SecurityAgent, and DepAuditAgent
and computes a weighted risk score (0–100).
"""

from __future__ import annotations

import structlog

from shared.models import RiskScore, ScanResult
from tools.risk_scorer import aggregate_findings_from_results, compute_risk_score

log = structlog.get_logger(__name__)


def run_risk_agent(
    scan_results: list[ScanResult],
    dep_scan_result: ScanResult,
    files_changed: int,
) -> RiskScore:
    """Compute the risk score from all scan results.

    Args:
        scan_results: Results from ScanAgent + SecurityAgent combined.
        dep_scan_result: Result from DepAuditAgent.
        files_changed: Number of files modified (code churn factor).

    Returns:
        RiskScore with score, label (LOW/MEDIUM/HIGH), and breakdown.
    """
    log.info("risk_agent_start", files_changed=files_changed)

    all_code_findings = aggregate_findings_from_results(scan_results)
    dep_findings = dep_scan_result.findings

    risk = compute_risk_score(
        all_findings=all_code_findings,
        dep_findings=dep_findings,
        files_changed=files_changed,
    )

    log.info(
        "risk_agent_complete",
        score=risk.score,
        label=risk.label,
        breakdown=risk.breakdown,
    )
    return risk
