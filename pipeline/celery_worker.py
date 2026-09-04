"""Celery application and task definition.

Each incoming webhook is processed as a Celery task, allowing horizontal
scaling by running multiple workers.
"""

from __future__ import annotations

import structlog
from celery import Celery

from pipeline.graph import pipeline
from pipeline.state import PipelineState
from shared.config import settings

log = structlog.get_logger(__name__)

# ── Celery app ────────────────────────────────────────────────────────────────
celery_app = Celery(
    "issue_to_pr",
    broker=settings.redis_url,
    backend=settings.redis_url,
)

celery_app.conf.update(
    task_serializer="json",
    result_serializer="json",
    accept_content=["json"],
    timezone="UTC",
    enable_utc=True,
    # Retry failed tasks once after 60 seconds
    task_acks_late=True,
    task_reject_on_worker_lost=True,
    # Task result expires after 24 hours
    result_expires=86400,
    # Limit task runtime to prevent runaway pipelines
    task_soft_time_limit=settings.agent_timeout_seconds * 10,
    task_time_limit=settings.agent_timeout_seconds * 12,
)


@celery_app.task(
    name="pipeline.run_pipeline",
    bind=True,
    max_retries=1,
    default_retry_delay=60,
)
def run_pipeline_task(
    self,
    issue_number: int,
    issue_title: str,
    issue_body: str,
    repo_owner: str,
    repo_name: str,
) -> dict:
    """Run the full Issue → PR pipeline for a single issue.

    Args:
        issue_number: GitHub issue number.
        issue_title: Issue title.
        issue_body: Issue body / description.
        repo_owner: Repository owner login.
        repo_name: Repository name.

    Returns:
        Dict with pipeline outcome (pr_url, risk_score, verdict, etc.)
    """
    log.info(
        "pipeline_task_start",
        task_id=self.request.id,
        issue=issue_number,
        repo=f"{repo_owner}/{repo_name}",
    )

    initial_state: PipelineState = {
        "issue_number": issue_number,
        "issue_title": issue_title,
        "issue_body": issue_body,
        "repo_owner": repo_owner,
        "repo_name": repo_name,
        "scan_results": [],
        "security_results": [],
        "committed_files": [],
        "remaining_findings": [],
        "auto_fixed_count": 0,
        "should_abort": False,
        "pipeline_error": None,
        "code_plan": None,
        "dep_scan_result": None,
        "risk_score": None,
        "pr_info": None,
        "scan_verdict": None,
        "security_verdict": None,
        "dep_verdict": None,
    }

    try:
        final_state: PipelineState = pipeline.invoke(initial_state)

        pr_info = final_state.get("pr_info")
        risk = final_state.get("risk_score")

        result = {
            "status": "success" if pr_info else "failed",
            "issue_number": issue_number,
            "pr_number": pr_info.number if pr_info else None,
            "pr_url": pr_info.url if pr_info else None,
            "risk_score": risk.score if risk else None,
            "risk_label": risk.label if risk else None,
            "auto_fixed": final_state.get("auto_fixed_count", 0),
            "remaining_findings": len(final_state.get("remaining_findings") or []),
            "error": final_state.get("pipeline_error"),
        }

        log.info("pipeline_task_complete", **result)
        return result

    except Exception as exc:
        log.error("pipeline_task_exception", error=str(exc), issue=issue_number)
        try:
            self.retry(exc=exc)
        except self.MaxRetriesExceededError:
            return {
                "status": "error",
                "issue_number": issue_number,
                "error": str(exc),
            }
