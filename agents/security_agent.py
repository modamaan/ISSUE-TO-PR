"""Agent ➍: SecurityAgent

Deep security scan using Semgrep (OWASP rules), OWASP regex patterns,
and detect-secrets. Operates on the cloned source directory.
"""

from __future__ import annotations

import shutil
import tempfile
from pathlib import Path

import git
import structlog

from shared.models import Finding, ScanResult
from shared.verdict import Severity, Verdict
from tools.secret_detector import run_detect_secrets
from tools.security_scanner import run_semgrep, scan_content_regex

log = structlog.get_logger(__name__)


def run_security_agent(
    repo_full_name: str,
    branch: str,
    github_token: str,
    committed_files: list[str],
) -> tuple[list[ScanResult], Verdict]:
    """Run Semgrep + OWASP regex + detect-secrets on the branch.

    Args:
        repo_full_name: 'owner/repo'
        branch: Branch to scan.
        github_token: PAT for authenticated clone.
        committed_files: List of files changed in this PR (for targeted regex scan).

    Returns:
        Tuple of (list of ScanResults, overall verdict).
    """
    log.info("security_agent_start", repo=repo_full_name, branch=branch)
    tmpdir = tempfile.mkdtemp(prefix="issue_to_pr_sec_")

    try:
        clone_url = f"https://{github_token}@github.com/{repo_full_name}.git"
        git.Repo.clone_from(clone_url, tmpdir, branch=branch, depth=1)
        source_dir = Path(tmpdir)

        # Run Semgrep on the whole directory
        semgrep_result = run_semgrep(source_dir)

        # Run OWASP regex scan on each committed file
        regex_findings: list[Finding] = []
        for rel_path in committed_files:
            file_path = source_dir / rel_path
            if file_path.exists() and file_path.is_file():
                content = file_path.read_text(encoding="utf-8", errors="replace")
                findings = scan_content_regex(content, filename=rel_path)
                regex_findings.extend(findings)

        regex_verdict = _findings_to_verdict(regex_findings)
        regex_result = ScanResult(
            tool="owasp-regex",
            findings=regex_findings,
            verdict=regex_verdict,
        )

        # Run detect-secrets
        secrets_result = run_detect_secrets(source_dir)

        results = [semgrep_result, regex_result, secrets_result]
        overall = _aggregate_verdict(results)

        crit_count = sum(
            1
            for r in results
            for f in r.findings
            if f.severity == Severity.CRITICAL
        )
        log.info(
            "security_agent_complete",
            branch=branch,
            critical_findings=crit_count,
            overall=overall,
        )
        return results, overall

    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


def _findings_to_verdict(findings: list[Finding]) -> Verdict:
    if any(f.severity == Severity.CRITICAL for f in findings):
        return Verdict.BLOCK
    if any(f.severity in (Severity.HIGH, Severity.MEDIUM) for f in findings):
        return Verdict.WARN
    return Verdict.PASS


def _aggregate_verdict(results: list[ScanResult]) -> Verdict:
    if any(r.verdict == Verdict.BLOCK for r in results):
        return Verdict.BLOCK
    if any(r.verdict == Verdict.WARN for r in results):
        return Verdict.WARN
    return Verdict.PASS
