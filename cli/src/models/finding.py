from __future__ import annotations
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Optional
import uuid


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFORMATIONAL = "INFORMATIONAL"
    UNKNOWN = "UNKNOWN"

    @property
    def numeric(self) -> float:
        return {
            "CRITICAL": 9.5, "HIGH": 7.5, "MEDIUM": 5.0,
            "LOW": 2.5, "INFORMATIONAL": 0.5, "UNKNOWN": 0.0,
        }[self.value]


class FindingSource(str, Enum):
    AWS_SECURITY_HUB = "aws_security_hub"
    GUARDDUTY = "guardduty"
    NESSUS = "nessus"
    OPENVAS = "openvas"
    CVE = "cve"
    KUBERNETES = "kubernetes"
    IAM = "iam"
    SAST = "sast"
    DEPENDENCY = "dependency"
    SECRETS = "secrets"
    GENERIC = "generic"


class AudienceMode(str, Enum):
    EXECUTIVE = "executive"
    MANAGER = "manager"
    DEVELOPER = "developer"
    SECURITY_ANALYST = "security_analyst"
    SOC_ANALYST = "soc_analyst"
    DEVSECOPS = "devsecops"
    GRC = "grc"


@dataclass
class AffectedAsset:
    resource_id: str
    resource_type: str
    resource_name: Optional[str] = None
    account_id: Optional[str] = None
    region: Optional[str] = None
    environment: Optional[str] = None
    tags: dict[str, str] = field(default_factory=dict)
    internet_facing: bool = False
    contains_sensitive_data: bool = False


@dataclass
class CVSSScore:
    base_score: float
    version: str = "3.1"
    vector: Optional[str] = None
    attack_vector: Optional[str] = None
    attack_complexity: Optional[str] = None
    privileges_required: Optional[str] = None
    user_interaction: Optional[str] = None
    confidentiality_impact: Optional[str] = None
    integrity_impact: Optional[str] = None
    availability_impact: Optional[str] = None
    exploitability_score: Optional[float] = None
    impact_score: Optional[float] = None


@dataclass
class NormalizedFinding:
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    source: FindingSource = FindingSource.GENERIC
    source_id: Optional[str] = None
    source_tool: Optional[str] = None
    title: str = ""
    description: str = ""
    finding_type: Optional[str] = None
    category: Optional[str] = None
    severity: Severity = Severity.UNKNOWN
    cvss: Optional[CVSSScore] = None
    cve_ids: list[str] = field(default_factory=list)
    affected_asset: Optional[AffectedAsset] = None
    risk_score: Optional[float] = None
    exploit_available: bool = False
    exploit_maturity: Optional[str] = None
    patch_available: bool = False
    days_since_discovered: Optional[int] = None
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    created_at: datetime = field(default_factory=datetime.utcnow)
    remediation_available: bool = False
    remediation_text: Optional[str] = None
    references: list[str] = field(default_factory=list)
    raw_data: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        if isinstance(self.severity, str):
            try:
                self.severity = Severity(self.severity.upper())
            except ValueError:
                self.severity = Severity.UNKNOWN

    @property
    def is_critical_or_high(self) -> bool:
        return self.severity in (Severity.CRITICAL, Severity.HIGH)

    @property
    def effective_risk_score(self) -> float:
        if self.risk_score is not None:
            return self.risk_score
        if self.cvss:
            return self.cvss.base_score
        return self.severity.numeric

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "source": self.source.value,
            "source_id": self.source_id,
            "source_tool": self.source_tool,
            "title": self.title,
            "description": self.description,
            "finding_type": self.finding_type,
            "category": self.category,
            "severity": self.severity.value,
            "cvss_score": self.cvss.base_score if self.cvss else None,
            "cve_ids": self.cve_ids,
            "risk_score": self.risk_score,
            "exploit_available": self.exploit_available,
            "affected_asset": {
                "resource_id": self.affected_asset.resource_id,
                "resource_type": self.affected_asset.resource_type,
                "resource_name": self.affected_asset.resource_name,
                "internet_facing": self.affected_asset.internet_facing,
                "contains_sensitive_data": self.affected_asset.contains_sensitive_data,
            } if self.affected_asset else None,
            "remediation_text": self.remediation_text,
            "references": self.references,
            "created_at": self.created_at.isoformat(),
        }


@dataclass
class Translation:
    finding_id: str
    audience: AudienceMode
    executive_summary: str = ""
    technical_explanation: str = ""
    business_impact: str = ""
    threat_scenario: str = ""
    risk_rating: str = ""
    remediation_steps: list[str] = field(default_factory=list)
    terraform_example: Optional[str] = None
    aws_cli_example: Optional[str] = None
    kubernetes_example: Optional[str] = None
    policy_recommendation: Optional[str] = None
    jira_ticket: Optional[dict[str, Any]] = None
    servicenow_ticket: Optional[dict[str, Any]] = None
    model_used: Optional[str] = None
    prompt_tokens: int = 0
    completion_tokens: int = 0
    generated_at: datetime = field(default_factory=datetime.utcnow)
