"""LangGraph pipeline state definition.

PipelineState flows through all 8 agents. Each agent reads what it needs
and writes its outputs back. LangGraph manages routing based on the state.
"""

from __future__ import annotations

from typing import TypedDict

from shared.models import CodePlan, Finding, PRInfo, RiskScore, ScanResult
from shared.verdict import Verdict


class PipelineState(TypedDict, total=False):
    """Shared state that flows through the entire agent pipeline."""

    # ── Input ─────────────────────────────────────────────────────────────────
    issue_number: int
    issue_title: str
    issue_body: str
    repo_owner: str
    repo_name: str

    # ── Agent outputs (populated as pipeline progresses) ──────────────────────
    code_plan: CodePlan | None                  # from IssueAnalyzerAgent
    committed_files: list[str]                  # from CodegenAgent
    scan_results: list[ScanResult]              # from ScanAgent
    scan_verdict: Verdict                       # from ScanAgent
    security_results: list[ScanResult]          # from SecurityAgent
    security_verdict: Verdict                   # from SecurityAgent
    dep_scan_result: ScanResult | None          # from DepAuditAgent
    dep_verdict: Verdict                        # from DepAuditAgent
    risk_score: RiskScore | None                # from RiskAgent
    auto_fixed_count: int                       # from AutoFixAgent
    remaining_findings: list[Finding]           # from AutoFixAgent
    pr_info: PRInfo | None                      # from PRCreatorAgent
    
    # ── Build Verification ────────────────────────────────────────────────────
    build_error: str | None                     # set if npm build fails
    build_retries: int                          # tracks codegen-build loop

    # ── Pipeline control ──────────────────────────────────────────────────────
    pipeline_error: str | None                  # set on unrecoverable error
    should_abort: bool                          # True → skip to error state
