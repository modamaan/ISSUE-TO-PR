"""Security scanner: Semgrep + OWASP regex patterns.

Two-pass approach:
  1. Regex pass — fast, deterministic, catches OWASP Top 10 patterns.
  2. Semgrep pass — deeper AST-level analysis using the owasp-top-ten ruleset.

The diff is analysed in unified-diff format (added lines only, with file:line).
"""

from __future__ import annotations

import json
import re
import subprocess
from pathlib import Path

import structlog

from shared.models import Finding, ScanResult
from shared.verdict import Severity, Verdict

log = structlog.get_logger(__name__)

# ── OWASP Regex patterns ──────────────────────────────────────────────────────
# Each entry: (pattern, description, severity, auto_fixable)
_PATTERNS: list[tuple[str, str, Severity, bool]] = [
    # SQL injection — string concatenation
    (
        r'"[^"\n]*(?:SELECT|UPDATE|DELETE|INSERT|WHERE|FROM)[^"\n]*"\s*\+',
        "SQL injection: SQL string built via concatenation",
        Severity.CRITICAL,
        True,
    ),
    # SQL injection — f-string
    (
        r"f[\"'][^\"']*(?:SELECT|UPDATE|DELETE|INSERT|WHERE|FROM)[^\"']*\{",
        "SQL injection: SQL f-string with interpolated variable",
        Severity.CRITICAL,
        True,
    ),
    # SQL injection — Python %-format
    (
        r"\"\'%s\'[^\"]*\"",
        "SQL injection: SQL string uses '%s' format (not parameterized)",
        Severity.CRITICAL,
        True,
    ),
    # execute() with a plain variable
    (
        r"\.execute\s*\(\s*(?:query|sql|stmt|cmd|q)\b",
        "SQL execute() called with a variable — verify parameterization",
        Severity.HIGH,
        False,
    ),
    # Hardcoded credential
    (
        r'(?:password|passwd|pwd|secret|api_key|apikey|auth_token)\s*=\s*["\'][^"\']{6,}["\']',
        "Hardcoded credential or secret",
        Severity.HIGH,
        True,
    ),
    # AWS access key
    (r"AKIA[0-9A-Z]{16}", "Hardcoded AWS access key", Severity.CRITICAL, True),
    # Private key
    (
        r"-----BEGIN (?:RSA|EC|DSA|OPENSSH) PRIVATE KEY-----",
        "Hardcoded private key",
        Severity.CRITICAL,
        False,
    ),
    # Command injection
    (
        r"(?:os\.system|subprocess\.(?:call|run|Popen))\s*\([^)]*\+",
        "Command injection: shell call built via string concatenation",
        Severity.HIGH,
        True,
    ),
    # Path traversal
    (
        r"open\s*\([^)]*(?:request\.|form\[|args\[|params\[|user)",
        "Path traversal: user-controlled input passed to open()",
        Severity.HIGH,
        False,
    ),
    # eval() with variable input
    (
        r"eval\s*\(\s*(?![\"\'])[^)]+\)",
        "eval() with non-literal argument — potential code injection",
        Severity.HIGH,
        True,
    ),
    # pickle.loads on untrusted data
    (
        r"pickle\.loads?\s*\(",
        "Unsafe pickle deserialization — potential RCE",
        Severity.HIGH,
        False,
    ),
    # Weak hash algorithms
    (
        r"hashlib\.(?:md5|sha1)\s*\(",
        "Weak cryptographic hash (MD5/SHA1) — use SHA-256+",
        Severity.MEDIUM,
        True,
    ),
    # Debug mode enabled
    (
        r"DEBUG\s*=\s*True",
        "Debug mode enabled — do not ship to production",
        Severity.MEDIUM,
        True,
    ),
    # assert used for security checks (removed by -O flag)
    (
        r"assert\s+.+(?:auth|permission|admin|role)",
        "Security check using assert — can be bypassed with -O flag",
        Severity.MEDIUM,
        True,
    ),
]

# Pre-compile all patterns for performance
_COMPILED = [
    (re.compile(pat, re.IGNORECASE), desc, sev, fixable)
    for pat, desc, sev, fixable in _PATTERNS
]


def scan_diff_regex(diff: str) -> list[Finding]:
    """Scan a unified diff for OWASP patterns (added lines only)."""
    findings: list[Finding] = []
    current_file: str | None = None
    current_line = 0

    for raw_line in diff.splitlines():
        if raw_line.startswith("+++ b/"):
            current_file = raw_line[6:]
            current_line = 0
        elif raw_line.startswith("@@ "):
            m = re.search(r"\+(\d+)", raw_line)
            current_line = int(m.group(1)) - 1 if m else 0
        elif raw_line.startswith("+") and not raw_line.startswith("+++"):
            current_line += 1
            content = raw_line[1:]  # strip leading '+'
            for compiled, desc, severity, auto_fixable in _COMPILED:
                if compiled.search(content):
                    findings.append(
                        Finding(
                            file=current_file or "unknown",
                            line=current_line,
                            rule_id="OWASP-REGEX",
                            severity=severity,
                            message=desc,
                            tool="owasp-regex",
                            auto_fixable=auto_fixable,
                        )
                    )

    return findings


def run_semgrep(source_dir: str | Path, timeout: int = 120) -> ScanResult:
    """Run Semgrep with OWASP Top-10 rules on `source_dir`."""
    source_dir = Path(source_dir)
    findings: list[Finding] = []

    try:
        result = subprocess.run(
            [
                "semgrep",
                "--config",
                "p/owasp-top-ten",
                "--config",
                "p/secrets",
                "--json",
                "--quiet",
                "--no-git-ignore",
                str(source_dir),
            ],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        raw_output = result.stdout or result.stderr

        data = json.loads(result.stdout) if result.stdout.strip() else {}
        for result_item in data.get("results", []):
            extra = result_item.get("extra", {})
            sev_raw = extra.get("severity", "WARNING").upper()
            severity_map = {
                "ERROR": Severity.CRITICAL,
                "WARNING": Severity.HIGH,
                "INFO": Severity.MEDIUM,
            }
            severity = severity_map.get(sev_raw, Severity.MEDIUM)
            findings.append(
                Finding(
                    file=result_item.get("path", "unknown"),
                    line=result_item.get("start", {}).get("line", 0),
                    rule_id=result_item.get("check_id", ""),
                    severity=severity,
                    message=extra.get("message", ""),
                    tool="semgrep",
                    auto_fixable=bool(extra.get("fix")),
                    fix_suggestion=extra.get("fix"),
                )
            )

        verdict = _derive_verdict(findings)
        log.info("semgrep_scan_complete", findings=len(findings), verdict=verdict)
        return ScanResult(tool="semgrep", findings=findings, verdict=verdict, raw_output=raw_output)

    except subprocess.TimeoutExpired:
        log.error("semgrep_timeout", timeout=timeout)
        return ScanResult(tool="semgrep", verdict=Verdict.WARN, error=f"Timeout after {timeout}s")
    except FileNotFoundError:
        log.warning("semgrep_not_found")
        return ScanResult(
            tool="semgrep", verdict=Verdict.PASS, error="semgrep not installed — skipped"
        )
    except (json.JSONDecodeError, KeyError) as exc:
        return ScanResult(tool="semgrep", verdict=Verdict.WARN, error=f"Parse error: {exc}")


def scan_content_regex(content: str, filename: str = "unknown") -> list[Finding]:
    """Scan raw file content (not a diff) for OWASP patterns."""
    findings: list[Finding] = []
    for i, line in enumerate(content.splitlines(), start=1):
        for compiled, desc, severity, auto_fixable in _COMPILED:
            if compiled.search(line):
                findings.append(
                    Finding(
                        file=filename,
                        line=i,
                        rule_id="OWASP-REGEX",
                        severity=severity,
                        message=desc,
                        tool="owasp-regex",
                        auto_fixable=auto_fixable,
                    )
                )
    return findings


def _derive_verdict(findings: list[Finding]) -> Verdict:
    if any(f.severity == Severity.CRITICAL for f in findings):
        return Verdict.BLOCK
    if any(f.severity in (Severity.HIGH, Severity.MEDIUM) for f in findings):
        return Verdict.WARN
    return Verdict.PASS
