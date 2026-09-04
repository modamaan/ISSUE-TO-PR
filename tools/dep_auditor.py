"""Dependency vulnerability audit using pip-audit.

pip-audit checks installed packages (or a requirements.txt) against
the PyPI Advisory Database and OSV for known CVEs.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import structlog

from shared.models import Finding, ScanResult
from shared.verdict import Severity, Verdict

log = structlog.get_logger(__name__)

# CVSS score thresholds for severity mapping
_CVSS_CRITICAL = 9.0
_CVSS_HIGH = 7.0
_CVSS_MEDIUM = 4.0


def _cvss_to_severity(cvss: float | None) -> Severity:
    if cvss is None:
        return Severity.MEDIUM  # unknown → assume medium
    if cvss >= _CVSS_CRITICAL:
        return Severity.CRITICAL
    if cvss >= _CVSS_HIGH:
        return Severity.HIGH
    if cvss >= _CVSS_MEDIUM:
        return Severity.MEDIUM
    return Severity.LOW


def run_pip_audit(source_dir: str | Path, timeout: int = 120) -> ScanResult:
    """Run pip-audit against the requirements.txt in `source_dir`.

    Args:
        source_dir: Root of the project being scanned.
        timeout: Maximum seconds to wait.

    Returns:
        ScanResult with a Finding per vulnerable dependency.
    """
    source_dir = Path(source_dir)
    findings: list[Finding] = []

    # Look for requirements file
    req_file = source_dir / "requirements.txt"
    if not req_file.exists():
        return ScanResult(
            tool="pip-audit",
            verdict=Verdict.PASS,
            raw_output="No requirements.txt found — skipped",
        )

    try:
        result = subprocess.run(
            [
                "pip-audit",
                "--requirement",
                str(req_file),
                "--format",
                "json",
                "--progress-spinner",
                "off",
                "--no-deps",  # only audit top-level deps (faster)
            ],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        raw_output = result.stdout or result.stderr

        # pip-audit exits 1 when vulnerabilities found, 0 when clean
        data = json.loads(result.stdout) if result.stdout.strip() else {}
        vulnerabilities: list[dict] = data.get("vulnerabilities", [])

        for vuln in vulnerabilities:
            package = vuln.get("name", "unknown")
            installed_version = vuln.get("version", "?")
            for detail in vuln.get("vulns", []):
                vuln_id = detail.get("id", "")
                description = detail.get("description", "")
                fix_versions = detail.get("fix_versions", [])
                cvss = detail.get("cvss", {})
                cvss_score = cvss.get("score") if isinstance(cvss, dict) else None

                severity = _cvss_to_severity(float(cvss_score) if cvss_score is not None else None)
                fix_suggestion = (
                    f"Upgrade {package} to {fix_versions[0]}" if fix_versions else None
                )

                findings.append(
                    Finding(
                        file="requirements.txt",
                        line=0,  # no line number for dep audits
                        rule_id=vuln_id,
                        severity=severity,
                        message=(
                            f"{package}=={installed_version} — {vuln_id}: {description[:120]}"
                        ),
                        tool="pip-audit",
                        auto_fixable=bool(fix_versions),
                        fix_suggestion=fix_suggestion,
                    )
                )

        verdict = _derive_verdict(findings)
        log.info("pip_audit_complete", findings=len(findings), verdict=verdict)
        return ScanResult(
            tool="pip-audit", findings=findings, verdict=verdict, raw_output=raw_output
        )

    except subprocess.TimeoutExpired:
        log.error("pip_audit_timeout", timeout=timeout)
        return ScanResult(
            tool="pip-audit", verdict=Verdict.WARN, error=f"Timeout after {timeout}s"
        )
    except FileNotFoundError:
        log.warning("pip_audit_not_found")
        return ScanResult(
            tool="pip-audit",
            verdict=Verdict.PASS,
            error="pip-audit not installed — skipped",
        )
    except (json.JSONDecodeError, KeyError) as exc:
        return ScanResult(tool="pip-audit", verdict=Verdict.WARN, error=f"Parse error: {exc}")


def _derive_verdict(findings: list[Finding]) -> Verdict:
    if any(f.severity == Severity.CRITICAL for f in findings):
        return Verdict.BLOCK
    if any(f.severity in (Severity.HIGH, Severity.MEDIUM) for f in findings):
        return Verdict.WARN
    return Verdict.PASS
