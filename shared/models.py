"""Core Pydantic models shared across all agents and tools."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field

from shared.verdict import Severity, Verdict

# ── Issue models ──────────────────────────────────────────────────────────────

class IssueType(StrEnum):
    BUG_FIX = "bug_fix"
    FEATURE = "feature"
    REFACTOR = "refactor"
    DOCS = "docs"
    UNKNOWN = "unknown"


class FileChange(BaseModel):
    """Describes a single file change the codegen agent should make."""

    path: str = Field(description="Repo-relative file path, e.g. 'src/utils.py'")
    action: str = Field(description="'create', 'modify', or 'delete'")
    description: str = Field(description="Human-readable description of the change")
    content: str | None = Field(
        default=None,
        description="Full file content (for create) or None (codegen will produce)",
    )


class CodePlan(BaseModel):
    """Structured plan produced by IssueAnalyzerAgent."""

    issue_type: IssueType
    summary: str = Field(description="One-sentence summary of the issue")
    branch_name: str = Field(description="Git branch name, e.g. 'fix/issue-42-null-check'")
    pr_title: str = Field(description="Proposed PR title")
    changes: list[FileChange] = Field(description="List of file changes to make")


# ── Security finding models ───────────────────────────────────────────────────

class Finding(BaseModel):
    """A single security/quality finding from any scanner."""

    file: str
    line: int
    rule_id: str = ""
    severity: Severity
    message: str
    tool: str = Field(description="Tool that produced this finding, e.g. 'bandit', 'semgrep'")
    auto_fixable: bool = False
    fix_suggestion: str | None = None


class ScanResult(BaseModel):
    """Aggregate result from a single scanning tool."""

    tool: str
    findings: list[Finding] = Field(default_factory=list)
    verdict: Verdict = Verdict.PASS
    raw_output: str = ""
    error: str | None = None

    @property
    def max_severity(self) -> Severity | None:
        if not self.findings:
            return None
        order = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]
        for s in order:
            if any(f.severity == s for f in self.findings):
                return s
        return None


# ── Risk score model ──────────────────────────────────────────────────────────

class RiskScore(BaseModel):
    """Weighted risk score 0–100 produced by RiskScorerAgent."""

    score: int = Field(ge=0, le=100)
    label: str = Field(description="'LOW', 'MEDIUM', or 'HIGH'")
    breakdown: dict[str, Any] = Field(
        default_factory=dict,
        description="Detailed breakdown of score components",
    )

    @property
    def is_high_risk(self) -> bool:
        return self.score >= 70


# ── PR models ─────────────────────────────────────────────────────────────────

class PRInfo(BaseModel):
    """Information about the opened pull request."""

    number: int
    url: str
    title: str
    branch: str
    is_draft: bool
    audit_comment_id: int | None = None


# ── Pipeline-level aggregate ──────────────────────────────────────────────────

class PipelineReport(BaseModel):
    """Full audit report assembled by PRCreatorAgent."""

    issue_number: int
    issue_title: str
    code_plan: CodePlan | None = None
    scan_results: list[ScanResult] = Field(default_factory=list)
    risk_score: RiskScore | None = None
    auto_fixed_count: int = 0
    remaining_findings: list[Finding] = Field(default_factory=list)
    pr: PRInfo | None = None
    pipeline_verdict: Verdict = Verdict.PASS
    error: str | None = None

    def to_markdown(self) -> str:
        """Render the report as a Markdown string for the PR description."""
        lines: list[str] = []

        # Header
        risk_label = self.risk_score.label if self.risk_score else "UNKNOWN"
        risk_score_val = self.risk_score.score if self.risk_score else "?"
        badge_color = {"LOW": "brightgreen", "MEDIUM": "yellow", "HIGH": "red"}.get(
            risk_label, "lightgrey"
        )
        lines.append("## 🛡️ IssueToPR — Security Audit Report\n")
        lines.append(
            f"![Risk Score](https://img.shields.io/badge/Risk_Score-{risk_score_val}%2F100-{badge_color})"
            f"  ![Verdict](https://img.shields.io/badge/Verdict-{self.pipeline_verdict.value}-{'red' if self.pipeline_verdict == Verdict.BLOCK else 'green'})\n"
        )

        # Summary table
        lines.append("### Summary\n")
        lines.append("| Metric | Value |")
        lines.append("|--------|-------|")
        lines.append(f"| Issue | #{self.issue_number} — {self.issue_title} |")
        lines.append(f"| Risk Score | {risk_score_val}/100 ({risk_label}) |")
        lines.append(f"| Overall Verdict | **{self.pipeline_verdict.value}** |")
        lines.append(f"| Auto-Fixed Vulnerabilities | {self.auto_fixed_count} |")
        lines.append(f"| Remaining Findings | {len(self.remaining_findings)} |")
        lines.append("")

        # Findings table
        if self.remaining_findings:
            lines.append("### ⚠️ Remaining Findings\n")
            lines.append("| Severity | File | Line | Tool | Message |")
            lines.append("|----------|------|------|------|---------|")
            for f in sorted(
                self.remaining_findings,
                key=lambda x: [
                    Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO
                ].index(x.severity),
            ):
                lines.append(
                    f"| `{f.severity.value}` | `{f.file}` | {f.line} | {f.tool} | {f.message} |"
                )
            lines.append("")

        # Scan results per tool
        lines.append("### Scan Results by Tool\n")
        for result in self.scan_results:
            emoji = "✅" if result.verdict == Verdict.PASS else ("⚠️" if result.verdict == Verdict.WARN else "🚨")
            lines.append(f"- {emoji} **{result.tool}**: {result.verdict.value} ({len(result.findings)} findings)")
        lines.append("")

        # Footer
        lines.append("---")
        lines.append("*Generated automatically by [IssueToPR](https://github.com/issue-to-pr)*")

        return "\n".join(lines)
