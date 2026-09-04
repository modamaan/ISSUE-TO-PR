"""Agent ➋: CodegenAgent

For each FileChange in the CodePlan:
1. Reads the existing file content from the branch (if it exists)
2. Calls the LLM to generate a new/modified version
3. Commits the file to the branch via GitHub API

The agent is intentionally conservative: it writes the minimal change
needed to address the issue, not a full rewrite.
"""

from __future__ import annotations

import structlog

from shared.config import settings
from shared.models import CodePlan, FileChange
from tools.github_client import GitHubClient
from tools.llm_client import chat_completion

log = structlog.get_logger(__name__)

_SYSTEM_PROMPT = """\
You are CodegenAgent, an expert software engineer in an automated Issue → PR pipeline.

Your task is to write production-quality code to implement a requested change.

Rules:
- Output ONLY the complete file content — no markdown fences, no explanations
- Write clean, readable, well-commented code
- Follow the existing code style if existing content is provided
- Do NOT introduce security vulnerabilities (SQL injection, hardcoded secrets, eval, etc.)
- Use parameterized queries, environment variables for secrets, input validation
- CRITICAL: Double-check all import paths. Ensure relative paths (e.g. '../_components/X') accurately point to existing directories and respect exact case-sensitivity. Do NOT invent or guess import paths.
- If deleting a file, output exactly: __DELETE_THIS_FILE__
"""


def run_codegen(
    plan: CodePlan,
    github_client: GitHubClient,
    issue_number: int,
    issue_body: str,
    build_error: str | None = None,
) -> list[str]:
    """Generate code for all file changes in the plan and commit to branch.

    Args:
        plan: The CodePlan from IssueAnalyzerAgent.
        github_client: Authenticated GitHub client.
        issue_number: GitHub issue number (for commit messages).
        issue_body: Original issue body (context for LLM).

    Returns:
        List of file paths that were successfully committed.
    """
    # Enforce max-files safety guard
    changes = plan.changes[: settings.max_files_per_issue]
    if len(plan.changes) > settings.max_files_per_issue:
        log.warning(
            "codegen_max_files_truncated",
            total=len(plan.changes),
            limit=settings.max_files_per_issue,
        )

    committed_files: list[str] = []

    for change in changes:
        try:
            _process_file_change(
                change=change,
                plan=plan,
                github_client=github_client,
                issue_number=issue_number,
                issue_body=issue_body,
                build_error=build_error,
            )
            committed_files.append(change.path)
        except Exception as exc:
            log.error(
                "codegen_file_failed",
                path=change.path,
                error=str(exc),
            )
            # Continue with remaining files; don't abort the whole pipeline

    log.info(
        "codegen_complete",
        branch=plan.branch_name,
        committed=len(committed_files),
        planned=len(changes),
    )
    return committed_files


def _process_file_change(
    change: FileChange,
    plan: CodePlan,
    github_client: GitHubClient,
    issue_number: int,
    issue_body: str,
    build_error: str | None,
) -> None:
    """Generate and commit a single file change."""
    log.info("codegen_file_start", path=change.path, action=change.action)

    if change.action == "delete":
        # TODO: GitHub API doesn't have a simple delete; we'd need to call
        # repo.delete_file() — skip for MVP, note it in PR body
        log.warning("codegen_delete_skipped", path=change.path)
        return

    # Read existing file content for context
    existing_content: str | None = None
    if change.action == "modify":
        existing_content = github_client.get_file_content(change.path, branch=plan.branch_name)
        if existing_content is None:
            # File doesn't exist yet — treat as create
            log.warning("codegen_file_not_found_treating_as_create", path=change.path)

    # Generate code
    new_content = _generate_code(
        change=change,
        plan=plan,
        existing_content=existing_content,
        issue_number=issue_number,
        issue_body=issue_body,
        build_error=build_error,
    )

    if new_content.strip() == "__DELETE_THIS_FILE__":
        log.warning("codegen_delete_marker_skipped", path=change.path)
        return

    # Commit to branch
    commit_message = (
        f"{_action_prefix(change.action)}: {change.path}\n\n"
        f"Closes #{issue_number} — {plan.summary}"
    )
    github_client.create_or_update_file(
        path=change.path,
        content=new_content,
        message=commit_message,
        branch=plan.branch_name,
    )
    log.info("codegen_file_committed", path=change.path, action=change.action)


def _generate_code(
    change: FileChange,
    plan: CodePlan,
    existing_content: str | None,
    issue_number: int,
    issue_body: str,
    build_error: str | None,
) -> str:
    """Call the LLM to generate file content."""
    context_section = (
        f"Existing file content:\n```\n{existing_content}\n```"
        if existing_content
        else "This is a new file."
    )

    feedback_section = ""
    if build_error:
        feedback_section = (
            f"\n\n!!! CRITICAL BUILD FAILURE !!!\n"
            f"Your previous attempt caused the following build error. "
            f"You MUST fix the code to resolve this error:\n```\n{build_error[-2000:]}\n```"
        )

    user_prompt = f"""\
Issue #{issue_number}: {plan.summary}

Issue description:
{issue_body or "(none)"}

Task: {change.description}

File: {change.path}
Action: {change.action}

{context_section}{feedback_section}

Write the complete {change.path} file content:
"""

    return chat_completion(
        system_prompt=_SYSTEM_PROMPT,
        user_prompt=user_prompt,
        temperature=0.2,
        max_tokens=4096,
    )


def _action_prefix(action: str) -> str:
    return {"create": "feat", "modify": "fix", "delete": "chore"}.get(action, "chore")
