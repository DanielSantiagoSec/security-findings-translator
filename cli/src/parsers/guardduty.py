from __future__ import annotations
import logging
from datetime import datetime
from typing import Any
from ..models.finding import AffectedAsset, FindingSource, NormalizedFinding, Severity
from .base import BaseParser

logger = logging.getLogger(__name__)

def _gd_severity(score: float) -> Severity:
    if score >= 7.0:
        return Severity.HIGH
    if score >= 4.0:
        return Severity.MEDIUM
    if score >= 1.0:
        return Severity.LOW
    return Severity.INFORMATIONAL

class GuardDutyParser(BaseParser):
    def can_parse(self, data: Any) -> bool:
        if isinstance(data, list):
            return len(data) > 0 and self.can_parse(data[0])
        if not isinstance(data, dict):
            return False
        has_gd_fields = all(k in data for k in ("type", "severity", "service"))
        is_gd_type = isinstance(data.get("type"), str) and "/" in data.get("type", "")
        return has_gd_fields and is_gd_type

    def parse(self, data: Any) -> list[NormalizedFinding]:
        findings_raw = data if isinstance(data, list) else [data]
        results = []
        for raw in findings_raw:
            try:
                results.append(self._parse_one(raw))
            except Exception as e:
                logger.error(f"Failed to parse GuardDuty finding {raw.get('id', '?')}: {e}")
        return results

    def _parse_one(self, raw: dict) -> NormalizedFinding:
        resource = raw.get("resource", {})
        resource_type = resource.get("resourceType", "Unknown")
        asset_id = "unknown"
        asset_name = None
        region = raw.get("region", None)
        account_id = raw.get("accountId", None)
        if resource_type == "Instance":
            inst = resource.get("instanceDetails", {})
            asset_id = inst.get("instanceId", "unknown")
            asset_name = next(
                (t["value"] for t in inst.get("tags", []) if t.get("key") == "Name"),
                inst.get("instanceId")
            )
        elif resource_type == "S3Bucket":
            buckets = resource.get("s3BucketDetails", [{}])
            bucket = buckets[0] if buckets else {}
            asset_id = bucket.get("name", "unknown")
            asset_name = bucket.get("name")
        elif resource_type == "AccessKey":
            key = resource.get("accessKeyDetails", {})
            asset_id = key.get("accessKeyId", "unknown")
            asset_name = key.get("userName")
        else:
            asset_id = resource_type
        affected_asset = AffectedAsset(
            resource_id=asset_id,
            resource_type=resource_type,
            resource_name=asset_name,
            account_id=account_id,
            region=region,
        )
        severity_val = float(raw.get("severity", 0))
        service = raw.get("service", {})
        action = service.get("action", {})
        action_type = action.get("actionType", "")
        description = raw.get("description", "")
        if action_type:
            description = f"[{action_type}] {description}"
        return NormalizedFinding(
            source=FindingSource.GUARDDUTY,
            source_id=raw.get("id"),
            source_tool="AWS GuardDuty",
            title=raw.get("title", "GuardDuty Finding"),
            description=description,
            finding_type=raw.get("type"),
            category=raw.get("type", "").split(":")[0] if ":" in raw.get("type", "") else None,
            severity=_gd_severity(severity_val),
            affected_asset=affected_asset,
            first_seen=self._parse_ts(raw.get("service", {}).get("eventFirstSeen")),
            last_seen=self._parse_ts(raw.get("service", {}).get("eventLastSeen")),
            remediation_available=True,
            raw_data=raw,
        )

    def _parse_ts(self, ts_str):
        if not ts_str:
            return None
        try:
            return datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
        except Exception:
            return None
