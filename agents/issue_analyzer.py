"""Agent ➊: IssueAnalyzerAgent

Reads a GitHub Issue and produces a structured CodePlan:
- Classifies the issue type (bug_fix, feature, refactor, docs)
- Lists specific files to create/modify and what to do
- Proposes a branch name and PR title
"""

from __future__ import annotations

import json
import re

import structlog

from shared.models import CodePlan, FileChange, IssueType
from tools.github_client import GitHubClient
from tools.llm_client import chat_completion_json

log = structlog.get_logger(__name__)

_SYSTEM_PROMPT = """\
You are IssueAnalyzerAgent, part of an automated GitHub Issue → Pull Request pipeline.

Your job is to analyze a GitHub issue and produce a structured plan for implementing a fix or feature.

You MUST respond with valid JSON matching this exact schema:
{
  "issue_type": "bug_fix" | "feature" | "refactor" | "docs" | "unknown",
  "summary": "<one sentence summary of what needs to be done>",
  "branch_name": "<git-branch-name, e.g. fix/issue-42-null-check>",
  "pr_title": "<concise PR title>",
  "changes": [
    {
      "path": "<repo-relative file path>",
      "action": "create" | "modify" | "delete",
      "description": "<what change to make in this file>"
    }
  ]
}

Rules:
- branch_name must be kebab-case, max 60 chars, start with fix/ or feat/ or docs/ or refactor/
- changes list should have 1–10 items
- Be specific about what code change is needed per file
- Do NOT include content in the JSON (CodegenAgent will write the actual code)
- CRITICAL: Only reference file paths that exist in the provided Repository File Tree, unless you are creating a brand new file.
"""


def run_issue_analyzer(
    issue_number: int,
    issue_title: str,
    issue_body: str,
    github_client: GitHubClient,
) -> CodePlan:
    """Analyze a GitHub issue and return a CodePlan.

    Args:
        issue_number: GitHub issue number (used for branch naming).
        issue_title: Issue title.
        issue_body: Issue body/description.
        github_client: GitHub client to fetch context.

    Returns:
        Structured CodePlan ready for CodegenAgent.
    """
    log.info("issue_analyzer_start", issue=issue_number, title=issue_title)
    
    repo_tree = github_client.get_repo_tree()
    tree_context = "\n".join(repo_tree) if repo_tree else "(No file tree available)"

    user_prompt = f"""\
GitHub Issue #{issue_number}: {issue_title}

Issue Description:
{issue_body or "(no description provided)"}

Repository File Tree:
```
{tree_context}
```

Analyze this issue and produce the implementation plan JSON.
"""

    raw = chat_completion_json(
        system_prompt=_SYSTEM_PROMPT,
        user_prompt=user_prompt,
        temperature=0.1,
        max_tokens=2048,
    )

    try:
        data = json.loads(raw)
        # Ensure branch name includes the issue number
        branch = data.get("branch_name", f"fix/issue-{issue_number}")
        if str(issue_number) not in branch:
            branch = f"{branch.rstrip('-')}-{issue_number}"
        data["branch_name"] = _sanitize_branch_name(branch)

        plan = CodePlan(
            issue_type=IssueType(data.get("issue_type", "unknown")),
            summary=data.get("summary", issue_title),
            branch_name=data["branch_name"],
            pr_title=data.get("pr_title", f"Fix: {issue_title}"),
            changes=[
                FileChange(
                    path=c["path"],
                    action=c["action"],
                    description=c["description"],
                )
                for c in data.get("changes", [])
            ],
        )
        log.info(
            "issue_analyzer_complete",
            issue=issue_number,
            branch=plan.branch_name,
            files=len(plan.changes),
            issue_type=plan.issue_type,
        )
        return plan

    except (json.JSONDecodeError, KeyError, ValueError) as exc:
        log.error("issue_analyzer_parse_failed", error=str(exc), raw=raw[:200])
        # Fallback plan
        return CodePlan(
            issue_type=IssueType.UNKNOWN,
            summary=issue_title,
            branch_name=f"fix/issue-{issue_number}",
            pr_title=f"Fix: #{issue_number} — {issue_title}",
            changes=[],
        )


def _sanitize_branch_name(name: str) -> str:
    """Sanitize a branch name: lowercase, replace invalid chars, max 60 chars."""
    name = name.lower()
    name = re.sub(r"[^a-z0-9/\-_]", "-", name)
    name = re.sub(r"-{2,}", "-", name)
    return name[:60].rstrip("-")
