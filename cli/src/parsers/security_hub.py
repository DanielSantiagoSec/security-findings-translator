from __future__ import annotations
import logging
from datetime import datetime
from typing import Any
from ..models.finding import AffectedAsset, CVSSScore, FindingSource, NormalizedFinding, Severity
from .base import BaseParser

logger = logging.getLogger(__name__)

def _asff_severity(severity_dict: dict) -> Severity:
    label = severity_dict.get("Label", "").upper()
    if label == "CRITICAL": return Severity.CRITICAL
    if label == "HIGH": return Severity.HIGH
    if label == "MEDIUM": return Severity.MEDIUM
    if label == "LOW": return Severity.LOW
    if label == "INFORMATIONAL": return Severity.INFORMATIONAL
    normalized = severity_dict.get("Normalized", 0)
    if normalized >= 90: return Severity.CRITICAL
    if normalized >= 70: return Severity.HIGH
    if normalized >= 40: return Severity.MEDIUM
    if normalized >= 1: return Severity.LOW
    return Severity.INFORMATIONAL

class SecurityHubParser(BaseParser):
    def can_parse(self, data: Any) -> bool:
        if isinstance(data, list):
            return len(data) > 0 and self.can_parse(data[0])
        if isinstance(data, dict) and "Findings" in data:
            findings = data["Findings"]
            return len(findings) > 0 and self.can_parse(findings[0])
        if not isinstance(data, dict):
            return False
        return "SchemaVersion" in data and "ProductArn" in data

    def parse(self, data: Any) -> list[NormalizedFinding]:
        if isinstance(data, dict) and "Findings" in data:
            raw_list = data["Findings"]
        elif isinstance(data, list):
            raw_list = data
        else:
            raw_list = [data]
        results = []
        for raw in raw_list:
            try:
                results.append(self._parse_one(raw))
            except Exception as e:
                logger.error(f"Failed to parse Security Hub finding {raw.get('Id', '?')}: {e}")
        return results

    def _parse_one(self, raw: dict) -> NormalizedFinding:
        resources = raw.get("Resources", [{}])
        resource = resources[0] if resources else {}
        region = resource.get("Region") or raw.get("Region")
        account_id = raw.get("AwsAccountId")
        affected_asset = AffectedAsset(
            resource_id=resource.get("Id", "unknown"),
            resource_type=resource.get("Type", "Unknown"),
            region=region,
            account_id=account_id,
            tags=resource.get("Tags", {}),
        )
        cvss = None
        vulns = raw.get("Vulnerabilities", [])
        if vulns:
            for score_entry in vulns[0].get("Cvss", []):
                if score_entry.get("Version", "").startswith("3"):
                    cvss = CVSSScore(
                        base_score=score_entry.get("BaseScore", 0.0),
                        version=score_entry.get("Version", "3.1"),
                        vector=score_entry.get("BaseVector"),
                    )
                    break
        cve_ids = []
        for vuln in vulns:
            for ref in vuln.get("RelatedVulnerabilities", []):
                if ref.startswith("CVE-"):
                    cve_ids.append(ref)
        product_arn = raw.get("ProductArn", "")
        if "guardduty" in product_arn.lower():
            source = FindingSource.GUARDDUTY
            source_tool = "AWS GuardDuty (via Security Hub)"
        elif "inspector" in product_arn.lower():
            source = FindingSource.CVE
            source_tool = "AWS Inspector (via Security Hub)"
        elif "macie" in product_arn.lower():
            source = FindingSource.SECRETS
            source_tool = "AWS Macie (via Security Hub)"
        else:
            source = FindingSource.AWS_SECURITY_HUB
            source_tool = raw.get("ProductName", "AWS Security Hub")
        severity = _asff_severity(raw.get("Severity", {}))
        remediation = raw.get("Remediation", {})
        remediation_text = remediation.get("Recommendation", {}).get("Text")
        remediation_url = remediation.get("Recommendation", {}).get("Url")
        references = [remediation_url] if remediation_url else []
        first_seen = self._parse_ts(raw.get("FirstObservedAt") or raw.get("CreatedAt"))
        last_seen = self._parse_ts(raw.get("LastObservedAt") or raw.get("UpdatedAt"))
        return NormalizedFinding(
            source=source,
            source_id=raw.get("Id"),
            source_tool=source_tool,
            title=raw.get("Title", "Security Hub Finding"),
            description=raw.get("Description", ""),
            finding_type=raw.get("Types", [None])[0],
            category=raw.get("Category"),
            severity=severity,
            cvss=cvss,
            cve_ids=cve_ids,
            affected_asset=affected_asset,
            remediation_available=bool(remediation_text),
            remediation_text=remediation_text,
            references=references,
            first_seen=first_seen,
            last_seen=last_seen,
            raw_data=raw,
        )

    def _parse_ts(self, ts_str):
        if not ts_str:
            return None
        try:
            return datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
        except Exception:
            return None
