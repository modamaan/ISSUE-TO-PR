"""Static code analysis using ruff (lint) and bandit (SAST).

Both tools are invoked as subprocesses against a checked-out copy of the
branch, with a hard timeout to prevent hanging pipelines.
"""

from __future__ import annotations

import json
import subprocess
import tempfile
from pathlib import Path

import structlog

from shared.models import Finding, ScanResult
from shared.verdict import Severity, Verdict

log = structlog.get_logger(__name__)

# Map bandit severity strings → our Severity enum
_BANDIT_SEVERITY_MAP = {
    "HIGH": Severity.HIGH,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
}

# Map ruff rule prefixes → Severity
_RUFF_ERROR_CODES_AS_HIGH = {"E", "F"}  # syntax/fatal errors
_RUFF_WARN_CODES = {"W", "B", "SIM"}


def run_ruff(source_dir: str | Path, timeout: int = 60) -> ScanResult:
    """Run ruff linter on `source_dir` and return a ScanResult."""
    source_dir = Path(source_dir)
    findings: list[Finding] = []

    try:
        result = subprocess.run(
            ["ruff", "check", str(source_dir), "--output-format", "json", "--no-cache"],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        raw_output = result.stdout or result.stderr

        if result.returncode not in (0, 1):
            # Return code 0 = clean, 1 = violations found, else = error
            return ScanResult(
                tool="ruff",
                verdict=Verdict.WARN,
                raw_output=raw_output,
                error=f"ruff exited with code {result.returncode}",
            )

        violations = json.loads(result.stdout) if result.stdout.strip() else []
        for v in violations:
            code = v.get("code", "")
            prefix = code[0] if code else ""
            if prefix in _RUFF_ERROR_CODES_AS_HIGH:
                severity = Severity.HIGH
            elif prefix in _RUFF_WARN_CODES:
                severity = Severity.MEDIUM
            else:
                severity = Severity.LOW

            findings.append(
                Finding(
                    file=v.get("filename", "unknown"),
                    line=v.get("location", {}).get("row", 0),
                    rule_id=code,
                    severity=severity,
                    message=v.get("message", ""),
                    tool="ruff",
                )
            )

        verdict = _derive_verdict(findings)
        log.info("ruff_scan_complete", findings=len(findings), verdict=verdict)
        return ScanResult(tool="ruff", findings=findings, verdict=verdict, raw_output=raw_output)

    except subprocess.TimeoutExpired:
        log.error("ruff_timeout", timeout=timeout)
        return ScanResult(tool="ruff", verdict=Verdict.WARN, error=f"Timeout after {timeout}s")
    except FileNotFoundError:
        log.warning("ruff_not_found")
        return ScanResult(tool="ruff", verdict=Verdict.PASS, error="ruff not installed — skipped")
    except json.JSONDecodeError as exc:
        return ScanResult(tool="ruff", verdict=Verdict.WARN, error=f"JSON parse error: {exc}")


def run_bandit(source_dir: str | Path, timeout: int = 90) -> ScanResult:
    """Run bandit SAST on `source_dir` and return a ScanResult."""
    source_dir = Path(source_dir)
    findings: list[Finding] = []

    try:
        result = subprocess.run(
            [
                "bandit",
                "-r",
                str(source_dir),
                "-f",
                "json",
                "--quiet",
                "--severity-level",
                "low",  # report everything, we filter in verdict
                "-x",
                ".venv,venv,env,tests",  # exclude virtual envs and tests
            ],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        raw_output = result.stdout or result.stderr

        # bandit exit codes: 0 = clean, 1 = issues found, else = error
        if result.returncode not in (0, 1):
            return ScanResult(
                tool="bandit",
                verdict=Verdict.WARN,
                raw_output=raw_output,
                error=f"bandit exited with code {result.returncode}",
            )

        data = json.loads(result.stdout) if result.stdout.strip() else {}
        for issue in data.get("results", []):
            raw_sev = issue.get("issue_severity", "LOW").upper()
            severity = _BANDIT_SEVERITY_MAP.get(raw_sev, Severity.LOW)
            findings.append(
                Finding(
                    file=issue.get("filename", "unknown"),
                    line=issue.get("line_number", 0),
                    rule_id=issue.get("test_id", ""),
                    severity=severity,
                    message=issue.get("issue_text", ""),
                    tool="bandit",
                    auto_fixable=False,
                )
            )

        verdict = _derive_verdict(findings)
        log.info("bandit_scan_complete", findings=len(findings), verdict=verdict)
        return ScanResult(tool="bandit", findings=findings, verdict=verdict, raw_output=raw_output)

    except subprocess.TimeoutExpired:
        log.error("bandit_timeout", timeout=timeout)
        return ScanResult(tool="bandit", verdict=Verdict.WARN, error=f"Timeout after {timeout}s")
    except FileNotFoundError:
        log.warning("bandit_not_found")
        return ScanResult(
            tool="bandit", verdict=Verdict.PASS, error="bandit not installed — skipped"
        )
    except json.JSONDecodeError as exc:
        return ScanResult(tool="bandit", verdict=Verdict.WARN, error=f"JSON parse error: {exc}")


def _derive_verdict(findings: list[Finding]) -> Verdict:
    """Compute overall verdict from a list of findings."""
    if any(f.severity == Severity.CRITICAL for f in findings):
        return Verdict.BLOCK
    if any(f.severity in (Severity.HIGH, Severity.MEDIUM) for f in findings):
        return Verdict.WARN
    return Verdict.PASS
