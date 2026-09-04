"""LangGraph state machine wiring all 8 agents.

Pipeline flow:
  analyze_issue
    → codegen
      → scan          (ruff + bandit)
        → security    (semgrep + owasp regex + detect-secrets)
          → dep_audit (pip-audit)
            → risk_score
              → autofix
                → create_pr

Each node handles its own errors gracefully; only unrecoverable errors
(e.g. branch creation failure) abort the pipeline early.
"""

from __future__ import annotations

import structlog
from langgraph.graph import END, START, StateGraph
from langgraph.graph.state import CompiledStateGraph

from agents.autofix_agent import run_autofix_agent
from agents.build_agent import run_build_verification
from agents.codegen import run_codegen
from agents.dep_audit_agent import run_dep_audit_agent
from agents.issue_analyzer import run_issue_analyzer
from agents.pr_creator import run_pr_creator
from agents.risk_agent import run_risk_agent
from agents.scan_agent import run_scan_agent
from agents.security_agent import run_security_agent
from pipeline.state import PipelineState
from shared.config import settings
from shared.models import ScanResult
from shared.verdict import Verdict
from tools.github_client import GitHubClient

log = structlog.get_logger(__name__)


# ── Node functions ─────────────────────────────────────────────────────────────


def node_analyze_issue(state: PipelineState) -> PipelineState:
    """➊ Analyze issue and produce a CodePlan."""
    try:
        gh = GitHubClient()
        gh._repo = gh.get_repo_for(state["repo_owner"], state["repo_name"])  # noqa: SLF001
        
        plan = run_issue_analyzer(
            issue_number=state["issue_number"],
            issue_title=state["issue_title"],
            issue_body=state.get("issue_body", ""),
            github_client=gh,
        )
        # Create branch immediately after analysis
        gh.create_branch(plan.branch_name)

        return {**state, "code_plan": plan}
    except Exception as exc:
        log.error("node_analyze_issue_failed", error=str(exc))
        return {**state, "pipeline_error": str(exc), "should_abort": True}


def node_codegen(state: PipelineState) -> PipelineState:
    """➋ Generate code and commit to branch."""
    if state.get("should_abort"):
        return state
    plan = state.get("code_plan")
    if not plan or not plan.changes:
        log.warning("codegen_no_changes_in_plan")
        return {**state, "committed_files": []}

    try:
        gh = GitHubClient()
        gh._repo = gh.get_repo_for(state["repo_owner"], state["repo_name"])  # noqa: SLF001
        committed = run_codegen(
            plan=plan,
            github_client=gh,
            issue_number=state["issue_number"],
            issue_body=state.get("issue_body", ""),
            build_error=state.get("build_error"),
        )
        return {**state, "committed_files": committed}
    except Exception as exc:
        log.error("node_codegen_failed", error=str(exc))
        return {**state, "pipeline_error": str(exc), "should_abort": True}


def node_build_verification(state: PipelineState) -> PipelineState:
    """2.5 Verify Node.js build."""
    if state.get("should_abort"):
        return state
    plan = state.get("code_plan")
    if not plan:
        return state

    try:
        repo_full = f"{state['repo_owner']}/{state['repo_name']}"
        error = run_build_verification(
            repo_full_name=repo_full,
            branch=plan.branch_name,
            github_token=settings.github_token.get_secret_value(),
        )
        retries = state.get("build_retries", 0)
        if error:
            log.warning("node_build_verification_failed", retries=retries, error=error[:200])
            return {**state, "build_error": error, "build_retries": retries + 1}
        
        log.info("node_build_verification_success")
        return {**state, "build_error": None, "build_retries": retries}
    except Exception as exc:
        log.error("node_build_verification_error", error=str(exc))
        return {**state, "build_error": str(exc), "build_retries": state.get("build_retries", 0) + 1}


def node_scan(state: PipelineState) -> PipelineState:
    """➌ Static analysis (ruff + bandit)."""
    if state.get("should_abort"):
        return state
    plan = state.get("code_plan")
    if not plan:
        return state

    try:
        repo_full = f"{state['repo_owner']}/{state['repo_name']}"
        results, verdict = run_scan_agent(
            repo_full_name=repo_full,
            branch=plan.branch_name,
            github_token=settings.github_token.get_secret_value(),
        )
        return {**state, "scan_results": results, "scan_verdict": verdict}
    except Exception as exc:
        log.error("node_scan_failed", error=str(exc))
        # Non-fatal: continue pipeline with empty results
        return {
            **state,
            "scan_results": [],
            "scan_verdict": Verdict.WARN,
        }


def node_security(state: PipelineState) -> PipelineState:
    """➍ Security scan (Semgrep + OWASP regex + detect-secrets)."""
    if state.get("should_abort"):
        return state
    plan = state.get("code_plan")
    if not plan:
        return state

    try:
        repo_full = f"{state['repo_owner']}/{state['repo_name']}"
        results, verdict = run_security_agent(
            repo_full_name=repo_full,
            branch=plan.branch_name,
            github_token=settings.github_token.get_secret_value(),
            committed_files=state.get("committed_files", []),
        )
        return {**state, "security_results": results, "security_verdict": verdict}
    except Exception as exc:
        log.error("node_security_failed", error=str(exc))
        return {
            **state,
            "security_results": [],
            "security_verdict": Verdict.WARN,
        }


def node_dep_audit(state: PipelineState) -> PipelineState:
    """➎ Dependency CVE audit (pip-audit)."""
    if state.get("should_abort"):
        return state
    plan = state.get("code_plan")
    if not plan:
        return state

    try:
        repo_full = f"{state['repo_owner']}/{state['repo_name']}"
        result, verdict = run_dep_audit_agent(
            repo_full_name=repo_full,
            branch=plan.branch_name,
            github_token=settings.github_token.get_secret_value(),
        )
        return {**state, "dep_scan_result": result, "dep_verdict": verdict}
    except Exception as exc:
        log.error("node_dep_audit_failed", error=str(exc))
        return {
            **state,
            "dep_scan_result": ScanResult(tool="pip-audit", error=str(exc)),
            "dep_verdict": Verdict.WARN,
        }


def node_risk_score(state: PipelineState) -> PipelineState:
    """➏ Compute weighted risk score."""
    if state.get("should_abort"):
        return state

    all_scan = [
        *(state.get("scan_results") or []),
        *(state.get("security_results") or []),
    ]
    dep_result = state.get("dep_scan_result") or ScanResult(tool="pip-audit")
    files_changed = len(state.get("committed_files") or [])

    risk = run_risk_agent(
        scan_results=all_scan,
        dep_scan_result=dep_result,
        files_changed=files_changed,
    )
    return {**state, "risk_score": risk}


def node_autofix(state: PipelineState) -> PipelineState:
    """➐ Auto-fix CRITICAL/HIGH findings."""
    if state.get("should_abort"):
        return state
    plan = state.get("code_plan")
    if not plan:
        return state

    all_scan = [
        *(state.get("scan_results") or []),
        *(state.get("security_results") or []),
    ]

    try:
        gh = GitHubClient()
        gh._repo = gh.get_repo_for(state["repo_owner"], state["repo_name"])  # noqa: SLF001
        fixed_count, remaining = run_autofix_agent(
            scan_results=all_scan,
            branch=plan.branch_name,
            github_client=gh,
        )
        return {**state, "auto_fixed_count": fixed_count, "remaining_findings": remaining}
    except Exception as exc:
        log.error("node_autofix_failed", error=str(exc))
        all_findings = [f for r in all_scan for f in r.findings]
        return {**state, "auto_fixed_count": 0, "remaining_findings": all_findings}


def node_create_pr(state: PipelineState) -> PipelineState:
    """➑ Open the Pull Request."""
    plan = state.get("code_plan")

    if state.get("should_abort") or not plan:
        error_msg = state.get("pipeline_error", "Pipeline aborted — no PR created")
        log.error("node_create_pr_aborted", reason=error_msg)
        # Post error comment on the issue
        try:
            gh = GitHubClient()
            gh._repo = gh.get_repo_for(state["repo_owner"], state["repo_name"])  # noqa: SLF001
            gh.post_issue_comment(
                state["issue_number"],
                f"❌ **IssueToPR pipeline failed**\n\n```\n{error_msg}\n```",
            )
        except Exception:
            pass
        return state

    dep_result = state.get("dep_scan_result") or ScanResult(tool="pip-audit")
    risk = state.get("risk_score")
    if not risk:
        from tools.risk_scorer import compute_risk_score  # noqa: PLC0415

        risk = compute_risk_score([], [], 0)

    try:
        gh = GitHubClient()
        gh._repo = gh.get_repo_for(state["repo_owner"], state["repo_name"])  # noqa: SLF001
        pr_info = run_pr_creator(
            plan=plan,
            scan_results=[
                *(state.get("scan_results") or []),
                *(state.get("security_results") or []),
            ],
            dep_scan_result=dep_result,
            risk_score=risk,
            auto_fixed_count=state.get("auto_fixed_count", 0),
            remaining_findings=state.get("remaining_findings", []),
            issue_number=state["issue_number"],
            issue_title=state["issue_title"],
            github_client=gh,
            repo_owner=state["repo_owner"],
            repo_name=state["repo_name"],
        )
        # Post success comment on the issue
        gh.post_issue_comment(
            state["issue_number"],
            f"🤖 **IssueToPR** opened PR #{pr_info.number}: {pr_info.url}",
        )
        return {**state, "pr_info": pr_info}
    except Exception as exc:
        log.error("node_create_pr_failed", error=str(exc))
        return {**state, "pipeline_error": str(exc)}


# ── Graph definition ───────────────────────────────────────────────────────────


def build_pipeline() -> CompiledStateGraph:
    """Construct and compile the LangGraph pipeline."""
    graph = StateGraph(PipelineState)

    # Add all nodes
    graph.add_node("analyze_issue", node_analyze_issue)
    graph.add_node("codegen", node_codegen)
    graph.add_node("build_verification", node_build_verification)
    graph.add_node("scan", node_scan)
    graph.add_node("security", node_security)
    graph.add_node("dep_audit", node_dep_audit)
    graph.add_node("risk_score", node_risk_score)
    graph.add_node("autofix", node_autofix)
    graph.add_node("create_pr", node_create_pr)

    def route_build_result(state: PipelineState) -> str:
        if state.get("should_abort"):
            return "scan"
        error = state.get("build_error")
        if error and state.get("build_retries", 0) < 3:
            return "codegen"
        return "scan"

    # Linear edges: all nodes run in sequence, except build retry loop
    graph.add_edge(START, "analyze_issue")
    graph.add_edge("analyze_issue", "codegen")
    graph.add_edge("codegen", "build_verification")
    graph.add_conditional_edges("build_verification", route_build_result)
    graph.add_edge("scan", "security")
    graph.add_edge("security", "dep_audit")
    graph.add_edge("dep_audit", "risk_score")
    graph.add_edge("risk_score", "autofix")
    graph.add_edge("autofix", "create_pr")
    graph.add_edge("create_pr", END)

    return graph.compile()


# Module-level compiled pipeline
pipeline = build_pipeline()
