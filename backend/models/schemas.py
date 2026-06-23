from __future__ import annotations
from datetime import datetime
from typing import Any, Optional
from pydantic import BaseModel, EmailStr, Field, field_validator


class UserCreate(BaseModel):
    email: EmailStr
    password: str = Field(min_length=8)
    full_name: str = Field(min_length=1, max_length=255)


class UserLogin(BaseModel):
    email: EmailStr
    password: str


class UserOut(BaseModel):
    id: str
    email: str
    full_name: str
    role: str
    is_active: bool
    mfa_enabled: bool
    created_at: datetime
    model_config = {"from_attributes": True}


class TokenOut(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int


class RefreshTokenIn(BaseModel):
    refresh_token: str


class ProjectCreate(BaseModel):
    name: str = Field(min_length=1, max_length=255)
    description: Optional[str] = None


class ProjectOut(BaseModel):
    id: str
    name: str
    description: Optional[str]
    created_by: str
    created_at: datetime
    model_config = {"from_attributes": True}


class FindingOut(BaseModel):
    id: str
    project_id: str
    source: str
    source_tool: Optional[str]
    title: str
    description: Optional[str]
    severity: str
    cvss_score: Optional[float]
    cve_ids: Optional[list[str]]
    risk_score: Optional[float]
    risk_label: Optional[str]
    asset_id: Optional[str]
    asset_type: Optional[str]
    asset_name: Optional[str]
    asset_region: Optional[str]
    internet_facing: bool
    exploit_available: bool
    patch_available: bool
    status: str
    created_at: datetime
    model_config = {"from_attributes": True}


class FindingListOut(BaseModel):
    findings: list[FindingOut]
    total: int
    page: int
    page_size: int


class FindingStatusUpdate(BaseModel):
    status: str = Field(pattern="^(open|in_progress|resolved|accepted_risk|false_positive)$")


class UploadResult(BaseModel):
    upload_id: str
    filename: str
    findings_count: int
    findings_parsed: int
    findings_failed: int
    project_id: str
    status: str


class TranslateRequest(BaseModel):
    finding_id: str
    audience: str = Field(
        pattern="^(executive|manager|developer|security_analyst|soc_analyst|devsecops|grc)$"
    )
    context: Optional[dict[str, Any]] = None


class TranslationOut(BaseModel):
    id: str
    finding_id: str
    audience: str
    executive_summary: Optional[str]
    technical_explanation: Optional[str]
    business_impact: Optional[str]
    threat_scenario: Optional[str]
    risk_rating: Optional[str]
    remediation_steps: Optional[list[str]]
    terraform_example: Optional[str]
    aws_cli_example: Optional[str]
    kubernetes_example: Optional[str]
    policy_recommendation: Optional[str]
    jira_ticket: Optional[dict]
    extra_fields: Optional[dict]
    model_used: Optional[str]
    generated_at: datetime
    model_config = {"from_attributes": True}


class BulkTranslateRequest(BaseModel):
    finding_ids: list[str] = Field(max_length=50)
    audiences: list[str]

    @field_validator("audiences")
    @classmethod
    def validate_audiences(cls, v):
        valid = {"executive","manager","developer","security_analyst","soc_analyst","devsecops","grc"}
        for a in v:
            if a not in valid:
                raise ValueError(f"Invalid audience: {a}")
        return v


class SeverityCount(BaseModel):
    severity: str
    count: int


class DashboardStats(BaseModel):
    total_findings: int
    open_findings: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    resolved_this_week: int
    avg_risk_score: float
    severity_breakdown: list[SeverityCount]
    top_findings: list[FindingOut]


class JiraTicketRequest(BaseModel):
    finding_id: str
    project_key: str
    issue_type: str = "Bug"
    assignee: Optional[str] = None


class JiraTicketOut(BaseModel):
    ticket_key: str
    ticket_url: str
    summary: str
    status: str


class AWSPullRequest(BaseModel):
    project_id: str
    source: str = Field(pattern="^(security_hub|guardduty)$")
    region: str = "us-east-1"
    max_findings: int = Field(default=100, le=500)
    severity_filter: list[str] = ["CRITICAL", "HIGH"]


class AWSPullResult(BaseModel):
    findings_pulled: int
    findings_new: int
    findings_updated: int
    source: str
    region: str
