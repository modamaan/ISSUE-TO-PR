"""Pydantic schemas for incoming webhook payloads and API responses."""

from __future__ import annotations

from pydantic import BaseModel, Field


class GitHubUser(BaseModel):
    login: str
    id: int


class GitHubLabel(BaseModel):
    name: str
    color: str = ""


class GitHubIssue(BaseModel):
    number: int
    title: str
    body: str | None = None
    state: str
    html_url: str
    user: GitHubUser
    labels: list[GitHubLabel] = Field(default_factory=list)

    @property
    def label_names(self) -> list[str]:
        return [label.name for label in self.labels]


class GitHubRepository(BaseModel):
    id: int
    name: str
    full_name: str
    html_url: str
    default_branch: str = "main"


class IssueWebhookPayload(BaseModel):
    """GitHub issues webhook event payload (opened / labeled actions)."""

    action: str  # "opened", "labeled", "edited", etc.
    issue: GitHubIssue
    repository: GitHubRepository
    sender: GitHubUser


class WebhookResponse(BaseModel):
    accepted: bool
    job_id: str | None = None
    message: str = ""
