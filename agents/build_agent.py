"""Build Verification Agent

Runs `npm install` and `npm run build` to verify the generated JavaScript/Next.js code compiles successfully.
Clones the branch to a temp directory and runs the build locally.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
from pathlib import Path

import git
import structlog

log = structlog.get_logger(__name__)


def run_build_verification(
    repo_full_name: str,
    branch: str,
    github_token: str,
) -> str | None:
    """Clone branch and run npm install + npm run build.

    Args:
        repo_full_name: e.g. 'owner/repo'
        branch: Branch name to clone.
        github_token: PAT for authenticated clone.

    Returns:
        None if the build succeeds (or if no package.json is found).
        A string containing the build error (stdout/stderr) if it fails.
    """
    log.info("build_verification_start", repo=repo_full_name, branch=branch)
    tmpdir = tempfile.mkdtemp(prefix="issue_to_pr_build_")

    try:
        clone_url = f"https://{github_token}@github.com/{repo_full_name}.git"
        git.Repo.clone_from(
            clone_url,
            tmpdir,
            branch=branch,
            depth=1,
        )
        log.info("build_verification_cloned", tmpdir=tmpdir)

        source_dir = Path(tmpdir)
        package_json = source_dir / "package.json"

        if not package_json.exists():
            log.info("build_verification_skipped", reason="no_package_json")
            return None

        # Run npm install
        log.info("build_verification_npm_install")
        install_proc = subprocess.run(
            ["npm", "install", "--no-fund", "--no-audit"],
            cwd=str(source_dir),
            capture_output=True,
            text=True,
        )
        if install_proc.returncode != 0:
            log.warning("build_verification_install_failed")
            return f"npm install failed:\n\n{install_proc.stderr}\n{install_proc.stdout}"

        # Run npm run build
        log.info("build_verification_npm_build")
        build_proc = subprocess.run(
            ["npm", "run", "build"],
            cwd=str(source_dir),
            capture_output=True,
            text=True,
        )
        if build_proc.returncode != 0:
            log.warning("build_verification_build_failed")
            return f"Build failed with exit code {build_proc.returncode}:\n\n{build_proc.stderr}\n{build_proc.stdout}"

        log.info("build_verification_success")
        return None

    except Exception as exc:
        log.error("build_verification_error", error=str(exc))
        return f"Build system error: {exc}"
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)
