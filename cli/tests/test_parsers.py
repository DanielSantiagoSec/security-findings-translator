import json
import sys
from pathlib import Path
import pytest

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from cli.src.models.finding import FindingSource, Severity
from cli.src.parsers.base import ParserFactory
from cli.src.parsers.guardduty import GuardDutyParser
from cli.src.parsers.security_hub import SecurityHubParser
from cli.src.parsers.nessus import NessusParser
from cli.src.parsers.generic_json import GenericJSONParser, GenericCSVParser


@pytest.fixture
def guardduty_finding():
    return {
        "id": "test-gd-001",
        "accountId": "123456789012",
        "region": "us-east-1",
        "type": "UnauthorizedAccess:EC2/SSHBruteForce",
        "title": "EC2 instance performing SSH brute force",
        "description": "EC2 instance is performing SSH brute force attacks.",
        "severity": 8.0,
        "service": {
            "action": {"actionType": "NETWORK_CONNECTION"},
            "eventFirstSeen": "2024-01-15T10:00:00Z",
            "eventLastSeen": "2024-01-15T10:45:00Z",
        },
        "resource": {
            "resourceType": "Instance",
            "instanceDetails": {
                "instanceId": "i-0abc123",
                "instanceType": "t3.medium",
                "tags": [{"key": "Name", "value": "prod-web-01"}],
            },
        },
    }


@pytest.fixture
def security_hub_finding():
    return {
        "Findings": [{
            "SchemaVersion": "2018-10-08",
            "Id": "arn:aws:securityhub:us-east-1:123456789012:finding/test001",
            "ProductArn": "arn:aws:securityhub:us-east-1::product/aws/inspector",
            "ProductName": "Inspector",
            "AwsAccountId": "123456789012",
            "Region": "us-east-1",
            "Types": ["Software and Configuration Checks/Vulnerabilities/CVE"],
            "FirstObservedAt": "2024-01-10T12:00:00Z",
            "LastObservedAt": "2024-01-16T09:00:00Z",
            "CreatedAt": "2024-01-10T12:00:00Z",
            "UpdatedAt": "2024-01-16T09:00:00Z",
            "Severity": {"Label": "CRITICAL", "Normalized": 95},
            "Title": "CVE-2021-44228 Log4Shell",
            "Description": "Remote code execution via Log4j JNDI lookup.",
            "Resources": [{
                "Type": "AwsEc2Instance",
                "Id": "arn:aws:ec2:us-east-1:123456789012:instance/i-0def456",
                "Region": "us-east-1",
            }],
            "Vulnerabilities": [{
                "Id": "CVE-2021-44228",
                "RelatedVulnerabilities": ["CVE-2021-44228"],
                "Cvss": [{"Version": "3.1", "BaseScore": 10.0}],
            }],
        }]
    }


class TestGuardDutyParser:
    def test_can_parse_single_finding(self, guardduty_finding):
        assert GuardDutyParser().can_parse(guardduty_finding) is True

    def test_rejects_non_guardduty(self):
        assert GuardDutyParser().can_parse({"SchemaVersion": "2018-10-08", "ProductArn": "x"}) is False

    def test_parses_title(self, guardduty_finding):
        findings = GuardDutyParser().parse(guardduty_finding)
        assert len(findings) == 1
        assert "SSH brute force" in findings[0].title

    def test_maps_severity_high(self, guardduty_finding):
        findings = GuardDutyParser().parse(guardduty_finding)
        assert findings[0].severity == Severity.HIGH

    def test_extracts_instance_id(self, guardduty_finding):
        findings = GuardDutyParser().parse(guardduty_finding)
        assert findings[0].affected_asset.resource_id == "i-0abc123"

    def test_extracts_source(self, guardduty_finding):
        findings = GuardDutyParser().parse(guardduty_finding)
        assert findings[0].source == FindingSource.GUARDDUTY

    def test_parses_list(self, guardduty_finding):
        findings = GuardDutyParser().parse([guardduty_finding, guardduty_finding])
        assert len(findings) == 2


class TestSecurityHubParser:
    def test_can_parse_asff_envelope(self, security_hub_finding):
        assert SecurityHubParser().can_parse(security_hub_finding) is True

    def test_parses_critical_severity(self, security_hub_finding):
        findings = SecurityHubParser().parse(security_hub_finding)
        assert findings[0].severity == Severity.CRITICAL

    def test_extracts_cve_ids(self, security_hub_finding):
        findings = SecurityHubParser().parse(security_hub_finding)
        assert "CVE-2021-44228" in findings[0].cve_ids

    def test_extracts_cvss_score(self, security_hub_finding):
        findings = SecurityHubParser().parse(security_hub_finding)
        assert findings[0].cvss.base_score == 10.0


class TestGenericJSONParser:
    def test_parses_simple_dict(self):
        findings = GenericJSONParser().parse({"title": "SQL Injection", "severity": "HIGH", "description": "Test"})
        assert findings[0].title == "SQL Injection"
        assert findings[0].severity == Severity.HIGH

    def test_parses_list(self):
        findings = GenericJSONParser().parse([{"title": "F1", "severity": "MEDIUM"}, {"title": "F2", "severity": "LOW"}])
        assert len(findings) == 2

    def test_handles_findings_wrapper(self):
        findings = GenericJSONParser().parse({"findings": [{"title": "Test", "severity": "HIGH"}]})
        assert len(findings) == 1

    def test_always_returns_something(self):
        assert len(GenericJSONParser().parse({})) == 1


class TestParserFactory:
    def test_selects_guardduty_parser(self, guardduty_finding):
        assert isinstance(ParserFactory.for_data(guardduty_finding), GuardDutyParser)

    def test_selects_security_hub_parser(self, security_hub_finding):
        assert isinstance(ParserFactory.for_data(security_hub_finding), SecurityHubParser)

    def test_falls_back_to_generic(self):
        assert isinstance(ParserFactory.for_data({"random": "data"}), GenericJSONParser)

    def test_from_file_json(self, tmp_path, guardduty_finding):
        f = tmp_path / "test.json"
        f.write_text(json.dumps([guardduty_finding]))
        findings = ParserFactory.from_file(f)
        assert findings[0].source == FindingSource.GUARDDUTY

    def test_from_file_not_found(self, tmp_path):
        with pytest.raises(FileNotFoundError):
            ParserFactory.from_file(tmp_path / "nope.json")
