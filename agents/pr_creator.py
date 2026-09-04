"""Agent ➑: PRCreatorAgent

Opens the Pull Request with a full security audit report as the description.
Posts inline review comments for any remaining (unfixed) findings.
"""

from __future__ import annotations

import structlog

from shared.config import settings
from shared.models import CodePlan, Finding, PipelineReport, PRInfo, RiskScore, ScanResult
from shared.verdict import Verdict
from tools.github_client import GitHubClient

log = structlog.get_logger(__name__)

# Labels to attach to every auto-generated PR
_BASE_LABELS = ["auto-generated", "security-reviewed"]


def run_pr_creator(
    plan: CodePlan,
    scan_results: list[ScanResult],
    dep_scan_result: ScanResult,
    risk_score: RiskScore,
    auto_fixed_count: int,
    remaining_findings: list[Finding],
    issue_number: int,
    issue_title: str,
    github_client: GitHubClient,
    repo_owner: str,
    repo_name: str,
) -> PRInfo:
    """Create the PR and post the audit report.

    Args:
        plan: The CodePlan (branch name, PR title, etc.)
        scan_results: Results from all code scanners.
        dep_scan_result: Result from pip-audit.
        risk_score: Computed risk score.
        auto_fixed_count: Number of findings auto-fixed.
        remaining_findings: Unfixed findings to post as inline comments.
        issue_number: GitHub issue number.
        issue_title: Issue title.
        github_client: Authenticated GitHub client.
        repo_owner: Repository owner.
        repo_name: Repository name.

    Returns:
        PRInfo with PR number, URL, and draft status.
    """
    log.info("pr_creator_start", branch=plan.branch_name, risk=risk_score.score)

    # Assemble the pipeline report
    all_results = [*scan_results, dep_scan_result]
    overall_verdict = _compute_overall_verdict(all_results)

    report = PipelineReport(
        issue_number=issue_number,
        issue_title=issue_title,
        code_plan=plan,
        scan_results=all_results,
        risk_score=risk_score,
        auto_fixed_count=auto_fixed_count,
        remaining_findings=remaining_findings,
        pipeline_verdict=overall_verdict,
    )

    pr_body = report.to_markdown()

    # Determine if PR should be draft
    is_draft = risk_score.is_high_risk

    # Labels
    labels = [*_BASE_LABELS, f"risk-{risk_score.label.lower()}"]

    # Override the GitHub client's internal repo if needed
    _set_client_repo(github_client, repo_owner, repo_name)

    # Open the PR
    pr = github_client.create_pull_request(
        title=f"{plan.pr_title} (closes #{issue_number})",
        body=pr_body,
        head_branch=plan.branch_name,
        base_branch="main",
        draft=is_draft,
        labels=labels,
    )

    # Post inline comments for remaining findings
    if remaining_findings:
        _post_inline_comments(
            pr_number=pr.number,
            findings=remaining_findings,
            branch=plan.branch_name,
            github_client=github_client,
        )

    pr_info = PRInfo(
        number=pr.number,
        url=pr.html_url,
        title=pr.title,
        branch=plan.branch_name,
        is_draft=is_draft,
    )

    log.info(
        "pr_creator_complete",
        pr_number=pr.number,
        url=pr.html_url,
        draft=is_draft,
        inline_comments=len(remaining_findings),
    )
    return pr_info


def _post_inline_comments(
    pr_number: int,
    findings: list[Finding],
    branch: str,
    github_client: GitHubClient,
) -> None:
    """Post inline review comments for each finding."""
    try:
        commit_sha = github_client.get_latest_commit_sha(branch)
    except Exception as exc:
        log.warning("pr_creator_sha_lookup_failed", error=str(exc))
        return

    for finding in findings[:20]:  # cap at 20 inline comments
        severity_emoji = {
            "CRITICAL": "🚨",
            "HIGH": "⚠️",
            "MEDIUM": "🔶",
            "LOW": "ℹ️",
        }.get(finding.severity.value, "•")

        comment_body = (
            f"{severity_emoji} **{finding.severity.value}** — {finding.message}\n\n"
            f"**Tool**: `{finding.tool}` | **Rule**: `{finding.rule_id}`\n"
        )
        if finding.fix_suggestion:
            comment_body += f"\n**Suggested fix**: {finding.fix_suggestion}"

        github_client.post_review_comment(
            pr_number=pr_number,
            body=comment_body,
            path=finding.file,
            line=finding.line,
            commit_sha=commit_sha,
        )


def _compute_overall_verdict(results: list[ScanResult]) -> Verdict:
    if any(r.verdict == Verdict.BLOCK for r in results):
        return Verdict.BLOCK
    if any(r.verdict == Verdict.WARN for r in results):
        return Verdict.WARN
    return Verdict.PASS


def _set_client_repo(
    github_client: GitHubClient,
    owner: str,
    name: str,
) -> None:
    """Point the client's cached repo to the correct owner/name."""

    # If the configured repo matches, use the cached repo
    if owner == settings.github_repo_owner and name == settings.github_repo_name:
        return

    # Otherwise get the specific repo
    github_client._repo = github_client.get_repo_for(owner, name)  # noqa: SLF001
