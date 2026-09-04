"""Unit tests for the risk scorer module."""

from __future__ import annotations

import pytest

from shared.models import Finding, ScanResult
from shared.verdict import Severity, Verdict
from tools.risk_scorer import aggregate_findings_from_results, compute_risk_score


def _make_finding(severity: Severity, file: str = "app.py", line: int = 1) -> Finding:
    return Finding(
        file=file,
        line=line,
        severity=severity,
        message="test finding",
        tool="test",
    )


class TestComputeRiskScore:
    """Tests for the weighted risk score formula."""

    def test_clean_code_scores_zero(self):
        risk = compute_risk_score([], [], files_changed=0)
        assert risk.score == 0
        assert risk.label == "LOW"

    def test_single_critical_finding(self):
        findings = [_make_finding(Severity.CRITICAL)]
        risk = compute_risk_score(findings, [], files_changed=0)
        assert risk.score == 30
        assert risk.label == "LOW"  # 30 < 40

    def test_multiple_critical_findings_cap_at_100(self):
        findings = [_make_finding(Severity.CRITICAL)] * 5  # 5 × 30 = 150 → capped
        risk = compute_risk_score(findings, [], files_changed=0)
        assert risk.score == 100
        assert risk.label == "HIGH"

    def test_high_finding_weight(self):
        findings = [_make_finding(Severity.HIGH)] * 3  # 3 × 15 = 45
        risk = compute_risk_score(findings, [], files_changed=0)
        assert risk.score == 45
        assert risk.label == "MEDIUM"

    def test_medium_finding_weight(self):
        findings = [_make_finding(Severity.MEDIUM)] * 8  # 8 × 5 = 40
        risk = compute_risk_score(findings, [], files_changed=0)
        assert risk.score == 40
        assert risk.label == "MEDIUM"

    def test_dep_crit_weighted_separately(self):
        dep_findings = [_make_finding(Severity.CRITICAL)]  # 1 × 25 = 25
        risk = compute_risk_score([], dep_findings, files_changed=0)
        assert risk.score == 25
        assert risk.breakdown["dep_score"] == 25
        assert risk.breakdown["code_score"] == 0

    def test_files_changed_contributes_to_score(self):
        risk = compute_risk_score([], [], files_changed=10)  # 10 × 0.5 = 5
        assert risk.score == 5
        assert risk.breakdown["churn_score"] == 5.0

    def test_combined_score(self):
        code_findings = [
            _make_finding(Severity.CRITICAL),  # 30
            _make_finding(Severity.HIGH),      # 15
        ]
        dep_findings = [_make_finding(Severity.HIGH)]  # 12
        risk = compute_risk_score(code_findings, dep_findings, files_changed=4)
        # 30 + 15 + 12 + 2 = 59
        assert risk.score == 59
        assert risk.label == "MEDIUM"

    def test_high_label_threshold(self):
        findings = [_make_finding(Severity.CRITICAL)] * 3  # 90
        risk = compute_risk_score(findings, [], files_changed=0)
        assert risk.label == "HIGH"
        assert risk.is_high_risk is True

    def test_low_label_threshold(self):
        findings = [_make_finding(Severity.LOW)] * 10  # 10
        risk = compute_risk_score(findings, [], files_changed=0)
        assert risk.label == "LOW"
        assert risk.is_high_risk is False

    def test_breakdown_fields_present(self):
        findings = [_make_finding(Severity.HIGH)]
        risk = compute_risk_score(findings, [], files_changed=3)
        for key in [
            "critical_findings", "high_findings", "medium_findings",
            "low_findings", "files_changed", "code_score", "dep_score",
            "churn_score", "raw_total",
        ]:
            assert key in risk.breakdown, f"Missing breakdown key: {key}"

    def test_score_capped_at_100(self):
        # Huge number of findings
        findings = [_make_finding(Severity.CRITICAL)] * 100
        risk = compute_risk_score(findings, [], files_changed=0)
        assert risk.score <= 100


class TestAggregateFindingsFromResults:
    """Tests for helper that flattens ScanResult lists."""

    def test_empty_results(self):
        assert aggregate_findings_from_results([]) == []

    def test_single_result(self):
        f = _make_finding(Severity.HIGH)
        result = ScanResult(tool="test", findings=[f], verdict=Verdict.WARN)
        findings = aggregate_findings_from_results([result])
        assert findings == [f]

    def test_multiple_results_flattened(self):
        f1 = _make_finding(Severity.CRITICAL)
        f2 = _make_finding(Severity.LOW)
        r1 = ScanResult(tool="ruff", findings=[f1], verdict=Verdict.BLOCK)
        r2 = ScanResult(tool="bandit", findings=[f2], verdict=Verdict.PASS)
        findings = aggregate_findings_from_results([r1, r2])
        assert len(findings) == 2
        assert f1 in findings
        assert f2 in findings
