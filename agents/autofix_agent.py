"""Agent ➐: AutoFixAgent  ← New capability not in DeployGuard

For each auto_fixable CRITICAL or HIGH finding, asks the LLM to patch
the affected code, then re-commits the fixed file to the branch.

After fixing, marks findings as resolved so they don't appear in the PR report.
"""

from __future__ import annotations

import structlog

from shared.models import Finding, ScanResult
from shared.verdict import Severity
from tools.github_client import GitHubClient
from tools.llm_client import chat_completion

log = structlog.get_logger(__name__)

_SYSTEM_PROMPT = """\
You are AutoFixAgent, a security engineer in an automated pipeline.

You will be given:
1. A security finding (file, line, severity, description)
2. The full content of the affected file

Your task: return the COMPLETE fixed file content with the vulnerability patched.

Rules:
- Output ONLY the complete file content — no markdown fences, no explanations, no commentary
- Make the minimal change necessary to fix the vulnerability
- Do NOT break existing functionality
- If the fix requires an environment variable instead of a hardcoded value, use os.environ.get("VAR_NAME")
- For SQL injection: use parameterized queries (cursor.execute(sql, (param,)))
- For command injection: use subprocess with a list argument, not a string
- For weak crypto: replace md5/sha1 with hashlib.sha256
- If you cannot safely fix the issue, output exactly: __CANNOT_FIX__
"""


def run_autofix_agent(
    scan_results: list[ScanResult],
    branch: str,
    github_client: GitHubClient,
) -> tuple[int, list[Finding]]:
    """Attempt to auto-fix CRITICAL and HIGH auto_fixable findings.

    Args:
        scan_results: All scan results from previous agents.
        branch: Branch to commit fixes to.
        github_client: Authenticated GitHub client.

    Returns:
        Tuple of (number of fixes applied, list of remaining unfixed findings).
    """
    log.info("autofix_agent_start", branch=branch)

    # Collect all fixable findings, deduplicated by file:line
    fixable: list[Finding] = []
    seen: set[str] = set()
    for result in scan_results:
        for finding in result.findings:
            key = f"{finding.file}:{finding.line}"
            if (
                finding.auto_fixable
                and finding.severity in (Severity.CRITICAL, Severity.HIGH)
                and key not in seen
            ):
                fixable.append(finding)
                seen.add(key)

    if not fixable:
        log.info("autofix_agent_no_fixable_findings")
        all_findings = [f for r in scan_results for f in r.findings]
        return 0, all_findings

    log.info("autofix_agent_fixable_count", count=len(fixable))

    # Group by file so we fix multiple issues in one file with one commit
    by_file: dict[str, list[Finding]] = {}
    for finding in fixable:
        by_file.setdefault(finding.file, []).append(finding)

    fixed_keys: set[str] = set()
    for filepath, file_findings in by_file.items():
        fixed_keys |= _fix_file(filepath, file_findings, branch, github_client)

    # Collect remaining (unfixed) findings
    remaining: list[Finding] = []
    for result in scan_results:
        for finding in result.findings:
            key = f"{finding.file}:{finding.line}"
            if key not in fixed_keys:
                remaining.append(finding)

    fix_count = len(fixed_keys)
    log.info("autofix_agent_complete", fixes_applied=fix_count, remaining=len(remaining))
    return fix_count, remaining


def _fix_file(
    filepath: str,
    findings: list[Finding],
    branch: str,
    github_client: GitHubClient,
) -> set[str]:
    """Fix all findings in a single file. Returns set of fixed 'file:line' keys."""
    log.info("autofix_file_start", path=filepath, findings=len(findings))

    current_content = github_client.get_file_content(filepath, branch=branch)
    if current_content is None:
        log.warning("autofix_file_not_found", path=filepath)
        return set()

    # Build the prompt describing all findings in this file
    findings_desc = "\n".join(
        f"  - Line {f.line}: [{f.severity.value}] {f.message}"
        for f in findings
    )

    user_prompt = f"""\
File: {filepath}

Security findings to fix:
{findings_desc}

Current file content:
```
{current_content}
```

Return the complete fixed file content:
"""

    fixed_content = chat_completion(
        system_prompt=_SYSTEM_PROMPT,
        user_prompt=user_prompt,
        temperature=0.1,
        max_tokens=8192,
    )

    if fixed_content.strip() == "__CANNOT_FIX__":
        log.warning("autofix_cannot_fix", path=filepath)
        return set()

    # Commit the fix
    commit_message = (
        f"security: auto-fix {len(findings)} finding(s) in {filepath}\n\n"
        + "\n".join(f"  - {f.message}" for f in findings)
    )
    try:
        github_client.create_or_update_file(
            path=filepath,
            content=fixed_content,
            message=commit_message,
            branch=branch,
        )
        log.info("autofix_file_committed", path=filepath)
        return {f"{filepath}:{f.line}" for f in findings}
    except Exception as exc:
        log.error("autofix_commit_failed", path=filepath, error=str(exc))
        return set()
