import sys
from pathlib import Path
import pytest

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from cli.src.engines.risk_engine import RiskContext, prioritize_findings, score_finding
from cli.src.models.finding import AffectedAsset, CVSSScore, NormalizedFinding, Severity


@pytest.fixture
def basic_finding():
    return NormalizedFinding(title="Test Finding", severity=Severity.HIGH)


@pytest.fixture
def finding_with_asset():
    return NormalizedFinding(
        title="Internet-Facing Finding",
        severity=Severity.MEDIUM,
        affected_asset=AffectedAsset(
            resource_id="i-123", resource_type="EC2",
            internet_facing=True, contains_sensitive_data=True, environment="prod",
        ),
    )


class TestRiskScoring:
    def test_basic_high_severity(self, basic_finding):
        result = score_finding(basic_finding, fetch_live_data=False)
        assert result.composite_score > 0
        assert result.base_score == Severity.HIGH.numeric

    def test_internet_facing_increases_score(self):
        base = NormalizedFinding(title="T", severity=Severity.MEDIUM)
        internet = NormalizedFinding(title="T", severity=Severity.MEDIUM)
        s1 = score_finding(base, RiskContext(internet_facing=False), fetch_live_data=False)
        s2 = score_finding(internet, RiskContext(internet_facing=True), fetch_live_data=False)
        assert s2.composite_score > s1.composite_score

    def test_sensitive_data_increases_score(self):
        f1 = NormalizedFinding(title="T", severity=Severity.MEDIUM)
        f2 = NormalizedFinding(title="T", severity=Severity.MEDIUM)
        s1 = score_finding(f1, RiskContext(contains_sensitive_data=False), fetch_live_data=False)
        s2 = score_finding(f2, RiskContext(contains_sensitive_data=True), fetch_live_data=False)
        assert s2.composite_score > s1.composite_score

    def test_dev_env_reduces_score(self):
        f1 = NormalizedFinding(title="T", severity=Severity.HIGH)
        f2 = NormalizedFinding(title="T", severity=Severity.HIGH)
        s_prod = score_finding(f1, RiskContext(environment="prod"), fetch_live_data=False)
        s_dev = score_finding(f2, RiskContext(environment="dev"), fetch_live_data=False)
        assert s_prod.composite_score > s_dev.composite_score

    def test_score_clamped_to_10(self):
        finding = NormalizedFinding(
            title="T", severity=Severity.CRITICAL, exploit_available=True,
            cvss=CVSSScore(base_score=10.0),
        )
        ctx = RiskContext(internet_facing=True, environment="prod", contains_sensitive_data=True)
        result = score_finding(finding, ctx, fetch_live_data=False)
        assert result.composite_score <= 10.0

    def test_score_non_negative(self):
        finding = NormalizedFinding(title="T", severity=Severity.INFORMATIONAL)
        result = score_finding(finding, RiskContext(environment="dev"), fetch_live_data=False)
        assert result.composite_score >= 0.0

    def test_cvss_used_when_available(self):
        finding = NormalizedFinding(
            title="T", severity=Severity.LOW,
            cvss=CVSSScore(base_score=9.8),
        )
        result = score_finding(finding, fetch_live_data=False)
        assert result.base_score == 9.8

    def test_scoring_method_label(self):
        finding = NormalizedFinding(title="T", severity=Severity.HIGH)
        result = score_finding(finding, fetch_live_data=False)
        assert result.scoring_method in ("severity", "cvss", "epss", "epss+cvss", "kev")

    def test_rationale_mentions_internet(self):
        finding = NormalizedFinding(title="T", severity=Severity.HIGH)
        result = score_finding(finding, RiskContext(internet_facing=True), fetch_live_data=False)
        assert "internet" in result.risk_rationale.lower()


class TestPrioritization:
    def test_highest_risk_first(self):
        findings = [
            NormalizedFinding(title="Low", severity=Severity.LOW),
            NormalizedFinding(title="Critical", severity=Severity.CRITICAL),
            NormalizedFinding(title="Medium", severity=Severity.MEDIUM),
        ]
        scored = prioritize_findings(findings, fetch_live_data=False)
        assert scored[0][0].title == "Critical"
        assert scored[-1][0].title == "Low"

    def test_updates_risk_score_on_finding(self):
        findings = [NormalizedFinding(title="T", severity=Severity.HIGH)]
        assert findings[0].risk_score is None
        prioritize_findings(findings, fetch_live_data=False)
        assert findings[0].risk_score is not None

    def test_handles_empty_list(self):
        assert prioritize_findings([], fetch_live_data=False) == []
