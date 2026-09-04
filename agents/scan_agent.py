"""Agent ➌: ScanAgent

Runs static analysis (ruff + bandit) on the generated code.
Clones the branch to a temp directory and runs tools locally.
"""

from __future__ import annotations

import os
import shutil
import tempfile
from pathlib import Path

import git
import structlog

from shared.models import ScanResult
from shared.verdict import Verdict
from tools.static_analyzer import run_bandit, run_ruff

log = structlog.get_logger(__name__)


def run_scan_agent(
    repo_full_name: str,
    branch: str,
    github_token: str,
) -> tuple[list[ScanResult], Verdict]:
    """Clone branch and run ruff + bandit.

    Args:
        repo_full_name: e.g. 'owner/repo'
        branch: Branch name to clone.
        github_token: PAT for authenticated clone.

    Returns:
        Tuple of (list of ScanResults, overall verdict).
    """
    log.info("scan_agent_start", repo=repo_full_name, branch=branch)
    tmpdir = tempfile.mkdtemp(prefix="issue_to_pr_")

    try:
        clone_url = f"https://{github_token}@github.com/{repo_full_name}.git"
        git.Repo.clone_from(
            clone_url,
            tmpdir,
            branch=branch,
            depth=1,  # shallow clone for speed
        )
        log.info("scan_agent_cloned", tmpdir=tmpdir)

        source_dir = Path(tmpdir)
        ruff_result = run_ruff(source_dir)
        bandit_result = run_bandit(source_dir)

        results = [ruff_result, bandit_result]
        overall = _aggregate_verdict(results)

        log.info(
            "scan_agent_complete",
            branch=branch,
            ruff_verdict=ruff_result.verdict,
            bandit_verdict=bandit_result.verdict,
            overall=overall,
        )
        return results, overall

    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


def _aggregate_verdict(results: list[ScanResult]) -> Verdict:
    if any(r.verdict == Verdict.BLOCK for r in results):
        return Verdict.BLOCK
    if any(r.verdict == Verdict.WARN for r in results):
        return Verdict.WARN
    return Verdict.PASS
