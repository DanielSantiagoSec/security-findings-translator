from __future__ import annotations
import csv
import io
import logging
from typing import Any
from ..models.finding import AffectedAsset, FindingSource, NormalizedFinding, Severity
from .base import BaseParser

logger = logging.getLogger(__name__)

_TITLE_FIELDS = ("title", "name", "finding_name", "vulnerability_name", "check_name",
                 "rule_name", "alert_name", "pluginName", "Title", "Name")
_DESC_FIELDS = ("description", "details", "info", "body", "message", "summary",
                "Description", "Details", "Info", "summary_text")
_SEVERITY_FIELDS = ("severity", "risk", "risk_factor", "priority", "level",
                    "Severity", "Risk", "Priority", "criticality", "impact")
_ID_FIELDS = ("id", "finding_id", "vulnerability_id", "alert_id", "Id", "ID",
              "cve_id", "rule_id", "check_id")
_ASSET_FIELDS = ("resource", "asset", "host", "target", "ip_address", "hostname",
                 "instance_id", "bucket_name", "resource_id", "Resource")
_REMEDIATION_FIELDS = ("remediation", "fix", "solution", "recommendation",
                       "Remediation", "Fix", "Solution", "how_to_fix")

def _coerce_severity(raw: Any) -> Severity:
    if raw is None:
        return Severity.UNKNOWN
    s = str(raw).strip().upper()
    for sev in Severity:
        if s == sev.value:
            return sev
    if s in ("CRIT", "CRITICAL", "P0", "1", "URGENT"): return Severity.CRITICAL
    if s in ("HIGH", "P1", "2", "IMPORTANT", "ERROR"): return Severity.HIGH
    if s in ("MED", "MEDIUM", "MODERATE", "P2", "3", "WARNING", "WARN"): return Severity.MEDIUM
    if s in ("LOW", "P3", "4", "MINOR", "INFO", "INFORMATIONAL"): return Severity.LOW
    try:
        score = float(s)
        if score >= 9.0: return Severity.CRITICAL
        if score >= 7.0: return Severity.HIGH
        if score >= 4.0: return Severity.MEDIUM
        if score >= 0.1: return Severity.LOW
    except ValueError:
        pass
    return Severity.UNKNOWN

def _extract_field(d: dict, candidates: tuple) -> Any:
    for key in candidates:
        if key in d and d[key] is not None:
            return d[key]
    return None

class GenericJSONParser(BaseParser):
    def can_parse(self, data: Any) -> bool:
        return isinstance(data, (dict, list))

    def parse(self, data: Any) -> list[NormalizedFinding]:
        if isinstance(data, list):
            raw_list = data
        elif isinstance(data, dict):
            for wrapper_key in ("findings", "vulnerabilities", "alerts", "results", "items", "data", "issues"):
                if wrapper_key in data and isinstance(data[wrapper_key], list):
                    raw_list = data[wrapper_key]
                    break
            else:
                raw_list = [data]
        else:
            raw_list = [{"raw": str(data)}]
        results = []
        for i, raw in enumerate(raw_list):
            try:
                if not isinstance(raw, dict):
                    raw = {"value": raw}
                results.append(self._parse_one(raw, i))
            except Exception as e:
                logger.error(f"GenericJSONParser: failed on item {i}: {e}")
        return results

    def _parse_one(self, raw: dict, index: int) -> NormalizedFinding:
        title = _extract_field(raw, _TITLE_FIELDS) or f"Finding #{index + 1}"
        description = _extract_field(raw, _DESC_FIELDS) or ""
        severity_raw = _extract_field(raw, _SEVERITY_FIELDS)
        severity = _coerce_severity(severity_raw)
        source_id = str(_extract_field(raw, _ID_FIELDS) or "")
        asset_raw = _extract_field(raw, _ASSET_FIELDS)
        remediation = _extract_field(raw, _REMEDIATION_FIELDS)
        asset = AffectedAsset(
            resource_id=str(asset_raw) if asset_raw else "unknown",
            resource_type="Unknown",
        ) if asset_raw else None
        return NormalizedFinding(
            source=FindingSource.GENERIC,
            source_id=source_id or None,
            source_tool="Unknown Security Tool",
            title=str(title),
            description=str(description),
            severity=severity,
            affected_asset=asset,
            remediation_text=str(remediation) if remediation else None,
            remediation_available=bool(remediation),
            raw_data=raw,
        )

class GenericCSVParser(BaseParser):
    def can_parse(self, data: Any) -> bool:
        if not isinstance(data, str):
            return False
        lines = data.strip().split("\n")
        return len(lines) >= 2 and "," in lines[0]

    def parse(self, data: Any) -> list[NormalizedFinding]:
        reader = csv.DictReader(io.StringIO(data))
        rows = list(reader)
        if not rows:
            return []
        results = []
        for i, row in enumerate(rows):
            try:
                json_parser = GenericJSONParser()
                finding = json_parser._parse_one(
                    {k.strip(): v.strip() for k, v in row.items()}, i
                )
                results.append(finding)
            except Exception as e:
                logger.error(f"GenericCSVParser: failed on row {i}: {e}")
        return results
