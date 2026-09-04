"""Authenticated GitHub client wrapper using PyGithub.

All GitHub interactions (reading issues, creating branches, committing files,
opening PRs, posting comments) go through this module.
"""

from __future__ import annotations

import base64
import logging

import structlog
from github import Github, GithubException
from github.ContentFile import ContentFile
from github.PullRequest import PullRequest
from github.Repository import Repository
from tenacity import (
    retry,
    retry_if_exception_type,
    stop_after_attempt,
    wait_exponential,
)

from shared.config import settings

log = structlog.get_logger(__name__)


def _make_github_client() -> Github:
    return Github(
        login_or_token=settings.github_token.get_secret_value(),
        retry=None,  # we handle retries ourselves via tenacity
    )


class GitHubClient:
    """Thin wrapper providing all GitHub operations needed by the pipeline."""

    def __init__(self) -> None:
        self._gh = _make_github_client()
        self._repo: Repository | None = None

    @property
    def repo(self) -> Repository:
        if self._repo is None:
            self._repo = self._gh.get_repo(settings.github_repo_full_name)
        return self._repo

    def get_repo_for(self, owner: str, name: str) -> Repository:
        """Return repository object for a specific owner/name."""
        return self._gh.get_repo(f"{owner}/{name}")

    # ── Branch operations ─────────────────────────────────────────────────────

    @retry(
        retry=retry_if_exception_type(GithubException),
        wait=wait_exponential(multiplier=1, min=2, max=30),
        stop=stop_after_attempt(4),
    )
    def create_branch(self, branch_name: str, base_branch: str = "main") -> str:
        """Create a new branch from `base_branch`. Returns branch name."""
        base_ref = self.repo.get_git_ref(f"heads/{base_branch}")
        sha = base_ref.object.sha
        ref_name = f"refs/heads/{branch_name}"
        try:
            self.repo.create_git_ref(ref=ref_name, sha=sha)
            log.info("branch_created", branch=branch_name, base=base_branch)
        except GithubException as exc:
            # Branch already exists — that's fine
            if exc.status == 422:
                log.warning("branch_already_exists", branch=branch_name)
            else:
                raise
        return branch_name

    # ── File operations ───────────────────────────────────────────────────────

    def get_file_content(self, path: str, branch: str = "main") -> str | None:
        """Return decoded file content from the repo, or None if not found."""
        try:
            content_file: ContentFile = self.repo.get_contents(path, ref=branch)  # type: ignore[assignment]
            return base64.b64decode(content_file.content).decode("utf-8")
        except GithubException as exc:
            if exc.status == 404:
                return None
            raise

    @retry(
        retry=retry_if_exception_type(GithubException),
        wait=wait_exponential(multiplier=1, min=2, max=30),
        stop=stop_after_attempt(4),
    )
    def create_or_update_file(
        self,
        path: str,
        content: str,
        message: str,
        branch: str,
    ) -> None:
        """Create or update a file on the given branch."""
        encoded = content.encode("utf-8")
        try:
            existing: ContentFile = self.repo.get_contents(path, ref=branch)  # type: ignore[assignment]
            self.repo.update_file(
                path=path,
                message=message,
                content=encoded,
                sha=existing.sha,
                branch=branch,
            )
            log.info("file_updated", path=path, branch=branch)
        except GithubException as exc:
            if exc.status == 404:
                self.repo.create_file(
                    path=path,
                    message=message,
                    content=encoded,
                    branch=branch,
                )
                log.info("file_created", path=path, branch=branch)
            else:
                raise

    def get_repo_tree(self, branch: str = "main") -> list[str]:
        """Return a list of all file paths in the repository for context."""
        try:
            ref = self.repo.get_git_ref(f"heads/{branch}")
            tree = self.repo.get_git_tree(ref.object.sha, recursive=True)
            return [element.path for element in tree.tree if element.type == "blob"]
        except GithubException as exc:
            log.warning("get_repo_tree_failed", error=str(exc))
            return []

    # ── Pull request operations ───────────────────────────────────────────────

    @retry(
        retry=retry_if_exception_type(GithubException),
        wait=wait_exponential(multiplier=1, min=2, max=30),
        stop=stop_after_attempt(4),
    )
    def create_pull_request(
        self,
        title: str,
        body: str,
        head_branch: str,
        base_branch: str = "main",
        draft: bool = False,
        labels: list[str] | None = None,
    ) -> PullRequest:
        """Open a PR and optionally attach labels."""
        pr = self.repo.create_pull(
            title=title,
            body=body,
            head=head_branch,
            base=base_branch,
            draft=draft,
        )
        log.info("pr_created", pr_number=pr.number, url=pr.html_url, draft=draft)

        if labels:
            for label_name in labels:
                try:
                    label = self.repo.get_label(label_name)
                    pr.add_to_labels(label)
                except GithubException:
                    # Label doesn't exist — create it
                    try:
                        self.repo.create_label(label_name, color="0075ca")
                        label = self.repo.get_label(label_name)
                        pr.add_to_labels(label)
                    except GithubException as label_exc:
                        log.warning("label_attach_failed", label=label_name, error=str(label_exc))
        return pr

    def post_pr_comment(self, pr_number: int, body: str) -> int:
        """Post a comment on a PR. Returns the comment ID."""
        pr = self.repo.get_pull(pr_number)
        comment = pr.create_issue_comment(body)
        log.info("pr_comment_posted", pr_number=pr_number, comment_id=comment.id)
        return comment.id

    def post_review_comment(
        self,
        pr_number: int,
        body: str,
        path: str,
        line: int,
        commit_sha: str,
    ) -> None:
        """Post an inline review comment at a specific file:line."""
        pr = self.repo.get_pull(pr_number)
        commit = self.repo.get_commit(commit_sha)
        try:
            pr.create_review_comment(
                body=body,
                commit=commit,
                path=path,
                line=line,
            )
        except GithubException as exc:
            log.warning(
                "inline_comment_failed",
                path=path,
                line=line,
                error=str(exc),
            )

    def get_latest_commit_sha(self, branch: str) -> str:
        """Return the SHA of the latest commit on a branch."""
        ref = self.repo.get_git_ref(f"heads/{branch}")
        return ref.object.sha

    def post_issue_comment(self, issue_number: int, body: str) -> None:
        """Post a comment on a GitHub Issue."""
        issue = self.repo.get_issue(issue_number)
        issue.create_comment(body)
        log.info("issue_comment_posted", issue_number=issue_number)


# Module-level singleton
github_client = GitHubClient()
