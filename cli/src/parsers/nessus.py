from __future__ import annotations
import logging
from typing import Any
from ..models.finding import AffectedAsset, CVSSScore, FindingSource, NormalizedFinding, Severity
from .base import BaseParser

logger = logging.getLogger(__name__)

def _nessus_severity(risk_factor: str) -> Severity:
    return {
        "Critical": Severity.CRITICAL, "High": Severity.HIGH,
        "Medium": Severity.MEDIUM, "Low": Severity.LOW,
        "None": Severity.INFORMATIONAL, "Info": Severity.INFORMATIONAL,
    }.get(risk_factor, Severity.UNKNOWN)

class NessusParser(BaseParser):
    def can_parse(self, data: Any) -> bool:
        if isinstance(data, dict):
            if "vulnerabilities" in data and "host" in data:
                return True
            if all(k in data for k in ("pluginID", "pluginName", "riskFactor")):
                return True
        if isinstance(data, list) and len(data) > 0:
            first = data[0]
            return isinstance(first, dict) and "pluginID" in first
        return False

    def parse(self, data: Any) -> list[NormalizedFinding]:
        if isinstance(data, dict) and "vulnerabilities" in data:
            host_ip = data.get("host", {}).get("ip", "unknown")
            host_name = data.get("host", {}).get("name", host_ip)
            vulns = data["vulnerabilities"]
        elif isinstance(data, list):
            host_ip = "unknown"
            host_name = "unknown"
            vulns = data
        else:
            host_ip = "unknown"
            host_name = "unknown"
            vulns = [data]
        results = []
        for vuln in vulns:
            try:
                results.append(self._parse_one(vuln, host_ip, host_name))
            except Exception as e:
                logger.error(f"Failed to parse Nessus finding: {e}")
        return results

    def _parse_one(self, raw: dict, host_ip: str, host_name: str) -> NormalizedFinding:
        cvss_score = raw.get("cvssBaseScore") or raw.get("cvss3BaseScore")
        cvss = CVSSScore(
            base_score=float(cvss_score),
            version="3.0" if raw.get("cvss3BaseScore") else "2.0",
            vector=raw.get("cvss3Vector") or raw.get("cvssVector"),
        ) if cvss_score else None
        cve_ids = []
        cve_raw = raw.get("cve", "")
        if cve_raw:
            cve_ids = [c.strip() for c in cve_raw.split(",") if c.strip().startswith("CVE-")]
        asset = AffectedAsset(resource_id=host_ip, resource_type="Host", resource_name=host_name)
        return NormalizedFinding(
            source=FindingSource.NESSUS,
            source_id=str(raw.get("pluginID", "")),
            source_tool="Tenable Nessus",
            title=raw.get("pluginName", "Nessus Finding"),
            description=raw.get("description", raw.get("synopsis", "")),
            finding_type=raw.get("pluginFamily"),
            severity=_nessus_severity(raw.get("riskFactor", "None")),
            cvss=cvss,
            cve_ids=cve_ids,
            affected_asset=asset,
            remediation_available=bool(raw.get("solution")),
            remediation_text=raw.get("solution"),
            references=[raw.get("seeAlso", "")] if raw.get("seeAlso") else [],
            patch_available=bool(raw.get("patch_publication_date")),
            raw_data=raw,
        )
