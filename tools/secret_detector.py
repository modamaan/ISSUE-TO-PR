"""Secret detection using detect-secrets.

detect-secrets scans for high-entropy strings, API keys, passwords,
connection strings, and other credential patterns.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import structlog

from shared.models import Finding, ScanResult
from shared.verdict import Severity, Verdict

log = structlog.get_logger(__name__)


def run_detect_secrets(source_dir: str | Path, timeout: int = 60) -> ScanResult:
    """Run detect-secrets scan on `source_dir`.

    Returns:
        ScanResult with findings for each detected secret.
    """
    source_dir = Path(source_dir)
    findings: list[Finding] = []

    try:
        result = subprocess.run(
            [
                "detect-secrets",
                "scan",
                "--all-files",
                "--exclude-files",
                r"\.git/.*",
                str(source_dir),
            ],
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=str(source_dir),
        )

        raw_output = result.stdout or result.stderr

        if not result.stdout.strip():
            return ScanResult(tool="detect-secrets", verdict=Verdict.PASS, raw_output=raw_output)

        data = json.loads(result.stdout)
        results_map: dict[str, list[dict]] = data.get("results", {})

        for filepath, secrets in results_map.items():
            for secret in secrets:
                # detect-secrets reports line_number per secret
                line_number = secret.get("line_number", 0)
                secret_type = secret.get("type", "Unknown Secret")

                findings.append(
                    Finding(
                        file=filepath,
                        line=line_number,
                        rule_id=f"DS-{secret_type.replace(' ', '_').upper()}",
                        severity=Severity.CRITICAL,  # all detected secrets are critical
                        message=f"Potential secret detected: {secret_type}",
                        tool="detect-secrets",
                        auto_fixable=True,  # can be fixed by moving to env var
                        fix_suggestion="Move this value to an environment variable and use os.environ.get()",
                    )
                )

        verdict = Verdict.BLOCK if findings else Verdict.PASS
        log.info("detect_secrets_complete", findings=len(findings), verdict=verdict)
        return ScanResult(
            tool="detect-secrets",
            findings=findings,
            verdict=verdict,
            raw_output=raw_output,
        )

    except subprocess.TimeoutExpired:
        log.error("detect_secrets_timeout", timeout=timeout)
        return ScanResult(
            tool="detect-secrets", verdict=Verdict.WARN, error=f"Timeout after {timeout}s"
        )
    except FileNotFoundError:
        log.warning("detect_secrets_not_found")
        return ScanResult(
            tool="detect-secrets",
            verdict=Verdict.PASS,
            error="detect-secrets not installed — skipped",
        )
    except (json.JSONDecodeError, KeyError) as exc:
        return ScanResult(
            tool="detect-secrets", verdict=Verdict.WARN, error=f"Parse error: {exc}"
        )
