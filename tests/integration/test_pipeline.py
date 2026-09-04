"""Integration tests for the webhook endpoint (mocked GitHub + OpenAI)."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient


def _make_sig(body: bytes, secret: str) -> str:
    return "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()


# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture(autouse=True)
def mock_settings(monkeypatch):
    """Patch settings so we don't need real env vars in tests."""
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test")
    monkeypatch.setenv("GITHUB_TOKEN", "ghp_test")
    monkeypatch.setenv("GITHUB_REPO_OWNER", "test-owner")
    monkeypatch.setenv("GITHUB_REPO_NAME", "test-repo")
    monkeypatch.setenv("GITHUB_WEBHOOK_SECRET", "test-secret")
    monkeypatch.setenv("REDIS_URL", "redis://localhost:6379/0")


@pytest.fixture
def client():
    # Import after patching env vars
    from api.main import app
    return TestClient(app)


# ── Health endpoint ────────────────────────────────────────────────────────────

class TestHealthEndpoint:
    def test_health_returns_ok(self, client):
        resp = client.get("/health")
        assert resp.status_code == 200
        assert resp.json()["status"] == "ok"


# ── Webhook endpoint ───────────────────────────────────────────────────────────

class TestWebhookEndpoint:
    WEBHOOK_SECRET = "test-secret"

    def _payload(self, action: str = "opened", labels: list = None) -> dict:
        return {
            "action": action,
            "issue": {
                "number": 42,
                "title": "Fix null pointer in auth module",
                "body": "When user logs in without a token, we get a NullPointerException.",
                "state": "open",
                "html_url": "https://github.com/test-owner/test-repo/issues/42",
                "user": {"login": "dev-user", "id": 123},
                "labels": labels or [],
            },
            "repository": {
                "id": 1,
                "name": "test-repo",
                "full_name": "test-owner/test-repo",
                "html_url": "https://github.com/test-owner/test-repo",
                "default_branch": "main",
            },
            "sender": {"login": "dev-user", "id": 123},
        }

    def _signed_request(self, client, payload: dict, event: str = "issues"):
        body = json.dumps(payload).encode()
        sig = _make_sig(body, self.WEBHOOK_SECRET)
        return client.post(
            "/webhook/issue",
            content=body,
            headers={
                "Content-Type": "application/json",
                "X-GitHub-Event": event,
                "X-Hub-Signature-256": sig,
            },
        )

    def test_invalid_signature_returns_401(self, client):
        payload = json.dumps(self._payload()).encode()
        resp = client.post(
            "/webhook/issue",
            content=payload,
            headers={
                "Content-Type": "application/json",
                "X-GitHub-Event": "issues",
                "X-Hub-Signature-256": "sha256=badhash",
            },
        )
        assert resp.status_code == 401

    def test_non_issues_event_ignored(self, client):
        resp = self._signed_request(client, self._payload(), event="push")
        assert resp.status_code == 202
        assert resp.json()["accepted"] is False

    def test_non_opened_action_ignored(self, client):
        resp = self._signed_request(client, self._payload(action="closed"))
        assert resp.status_code == 202
        assert resp.json()["accepted"] is False

    @patch("pipeline.celery_worker.run_pipeline_task.delay")
    def test_valid_issue_opened_enqueues_task(self, mock_delay, client):
        mock_task = MagicMock()
        mock_task.id = "task-uuid-123"
        mock_delay.return_value = mock_task

        resp = self._signed_request(client, self._payload(action="opened"))
        assert resp.status_code == 202
        data = resp.json()
        assert data["accepted"] is True
        assert data["job_id"] == "task-uuid-123"
        mock_delay.assert_called_once()

    @patch("pipeline.celery_worker.run_pipeline_task.delay")
    def test_labeled_action_enqueues_task(self, mock_delay, client):
        mock_task = MagicMock()
        mock_task.id = "task-uuid-456"
        mock_delay.return_value = mock_task

        resp = self._signed_request(client, self._payload(action="labeled"))
        assert resp.status_code == 202
        assert resp.json()["accepted"] is True
