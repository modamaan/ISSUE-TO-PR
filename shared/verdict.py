"""Severity and Verdict enumerations used across the pipeline."""

from __future__ import annotations

from enum import Enum


class Severity(str, Enum):
    """Finding severity levels (OWASP-aligned)."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

    @property
    def weight(self) -> int:
        """Numeric weight used in risk score calculation."""
        return {
            Severity.CRITICAL: 30,
            Severity.HIGH: 15,
            Severity.MEDIUM: 5,
            Severity.LOW: 1,
            Severity.INFO: 0,
        }[self]

    def is_blocking(self) -> bool:
        """Returns True for severities that halt the pipeline."""
        return self in (Severity.CRITICAL,)


class Verdict(str, Enum):
    """Overall verdict emitted by each agent."""

    PASS = "PASS"     # No issues found — proceed
    WARN = "WARN"     # Non-critical issues — proceed with caution
    BLOCK = "BLOCK"   # Critical issues — pipeline halted


# Convenience mapping: worst severity → verdict
SEVERITY_TO_VERDICT: dict[Severity, Verdict] = {
    Severity.CRITICAL: Verdict.BLOCK,
    Severity.HIGH: Verdict.WARN,
    Severity.MEDIUM: Verdict.WARN,
    Severity.LOW: Verdict.PASS,
    Severity.INFO: Verdict.PASS,
}
