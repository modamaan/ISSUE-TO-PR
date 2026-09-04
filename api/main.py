"""FastAPI application — webhook receiver entry point.

Endpoints:
    GET  /health              → liveness probe
    GET  /ready               → readiness probe (checks Redis)
    POST /webhook/issue       → GitHub issues webhook
"""

from __future__ import annotations

import logging

import structlog
from fastapi import FastAPI, Header, HTTPException, Request, status
from fastapi.responses import JSONResponse

from api.schemas import IssueWebhookPayload, WebhookResponse
from api.verifier import verify_signature
from pipeline.celery_worker import run_pipeline_task
from shared.config import settings

# ── Logging setup ─────────────────────────────────────────────────────────────
structlog.configure(
    wrapper_class=structlog.make_filtering_bound_logger(
        getattr(logging, settings.log_level)
    ),
)
log = structlog.get_logger(__name__)

# ── FastAPI app ───────────────────────────────────────────────────────────────
app = FastAPI(
    title="IssueToPR",
    description="Autonomous GitHub Issue → PR pipeline with multi-agent security scanning",
    version="0.1.0",
    docs_url="/docs",
    redoc_url="/redoc",
)


# ── Health / readiness ────────────────────────────────────────────────────────

@app.get("/health", tags=["ops"])
async def health() -> dict:
    """Liveness probe — always returns 200 if the process is up."""
    return {"status": "ok", "service": "issue-to-pr"}


@app.get("/ready", tags=["ops"])
async def ready() -> JSONResponse:
    """Readiness probe — checks Redis connectivity."""
    try:
        import redis as redis_lib  # noqa: PLC0415

        r = redis_lib.from_url(settings.redis_url, socket_connect_timeout=2)
        r.ping()
        return JSONResponse({"status": "ready"})
    except Exception as exc:
        log.warning("readiness_check_failed", error=str(exc))
        return JSONResponse({"status": "not_ready", "reason": str(exc)}, status_code=503)


# ── Webhook ───────────────────────────────────────────────────────────────────

@app.post(
    "/webhook/issue",
    status_code=status.HTTP_202_ACCEPTED,
    response_model=WebhookResponse,
    tags=["webhook"],
)
async def github_issue_webhook(
    request: Request,
    x_github_event: str = Header(default=""),
    x_hub_signature_256: str = Header(default=""),
) -> WebhookResponse:
    """Receive GitHub issues webhook events and enqueue the pipeline."""
    raw_body = await request.body()

    # 1. Verify HMAC signature
    if not verify_signature(
        raw_body,
        x_hub_signature_256,
        settings.github_webhook_secret.get_secret_value(),
    ):
        log.warning("invalid_webhook_signature")
        raise HTTPException(status_code=401, detail="Invalid webhook signature")

    # 2. Only handle 'issues' events
    if x_github_event != "issues":
        log.debug("ignored_event", gh_event=x_github_event)
        return WebhookResponse(accepted=False, message=f"Event '{x_github_event}' ignored")

    # 3. Parse payload
    try:
        payload = IssueWebhookPayload.model_validate_json(raw_body)
    except Exception as exc:
        log.error("payload_parse_error", error=str(exc))
        raise HTTPException(status_code=422, detail=f"Invalid payload: {exc}") from exc

    # 4. Only process 'opened' or 'labeled' actions
    if payload.action not in ("opened", "labeled"):
        return WebhookResponse(
            accepted=False,
            message=f"Action '{payload.action}' not processed",
        )

    # 5. If a label filter is configured, enforce it
    if (
        settings.github_issue_label
        and settings.github_issue_label not in payload.issue.label_names
    ):
        log.info(
            "issue_skipped_no_label",
            issue=payload.issue.number,
            required_label=settings.github_issue_label,
            present_labels=payload.issue.label_names,
        )
        return WebhookResponse(
            accepted=False,
            message=f"Issue does not have required label '{settings.github_issue_label}'",
        )

    # 6. Enqueue Celery task
    log.info(
        "enqueuing_pipeline",
        issue=payload.issue.number,
        title=payload.issue.title,
        gh_action=payload.action,
    )
    task = run_pipeline_task.delay(
        issue_number=payload.issue.number,
        issue_title=payload.issue.title,
        issue_body=payload.issue.body or "",
        repo_owner=payload.repository.full_name.split("/")[0],
        repo_name=payload.repository.name,
    )

    return WebhookResponse(
        accepted=True,
        job_id=task.id,
        message=f"Pipeline enqueued for issue #{payload.issue.number}",
    )
