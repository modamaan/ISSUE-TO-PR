"""Agent ➎: DepAuditAgent

Runs pip-audit against the requirements.txt on the branch to detect
known CVEs in dependencies.
"""

from __future__ import annotations

import shutil
import tempfile
from pathlib import Path

import git
import structlog

from shared.models import ScanResult
from shared.verdict import Verdict
from tools.dep_auditor import run_pip_audit

log = structlog.get_logger(__name__)


def run_dep_audit_agent(
    repo_full_name: str,
    branch: str,
    github_token: str,
) -> tuple[ScanResult, Verdict]:
    """Clone the branch and audit dependencies.

    Args:
        repo_full_name: 'owner/repo'
        branch: Branch to audit.
        github_token: PAT for clone.

    Returns:
        Tuple of (ScanResult from pip-audit, verdict).
    """
    log.info("dep_audit_agent_start", repo=repo_full_name, branch=branch)
    tmpdir = tempfile.mkdtemp(prefix="issue_to_pr_dep_")

    try:
        clone_url = f"https://{github_token}@github.com/{repo_full_name}.git"
        git.Repo.clone_from(clone_url, tmpdir, branch=branch, depth=1)

        result = run_pip_audit(source_dir=Path(tmpdir))

        log.info(
            "dep_audit_agent_complete",
            branch=branch,
            findings=len(result.findings),
            verdict=result.verdict,
        )
        return result, result.verdict

    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)
