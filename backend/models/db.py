from __future__ import annotations
import uuid
from datetime import datetime
from typing import Optional
from sqlalchemy import Boolean, DateTime, Float, ForeignKey, Integer, String, Text, JSON, func
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


def _uuid() -> str:
    return str(uuid.uuid4())


class Base(DeclarativeBase):
    pass


class User(Base):
    __tablename__ = "users"
    id: Mapped[str] = mapped_column(UUID(as_uuid=False), primary_key=True, default=_uuid)
    email: Mapped[str] = mapped_column(String(255), unique=True, nullable=False, index=True)
    hashed_password: Mapped[str] = mapped_column(String(255), nullable=False)
    full_name: Mapped[str] = mapped_column(String(255), nullable=False)
    role: Mapped[str] = mapped_column(String(50), default="analyst")
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    mfa_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    mfa_secret: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())
    last_login: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    projects: Mapped[list[ProjectMember]] = relationship(back_populates="user")
    audit_logs: Mapped[list[AuditLog]] = relationship(back_populates="user")


class Project(Base):
    __tablename__ = "projects"
    id: Mapped[str] = mapped_column(UUID(as_uuid=False), primary_key=True, default=_uuid)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    created_by: Mapped[str] = mapped_column(ForeignKey("users.id"), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())
    members: Mapped[list[ProjectMember]] = relationship(back_populates="project")
    findings: Mapped[list[Finding]] = relationship(back_populates="project")


class ProjectMember(Base):
    __tablename__ = "project_members"
    id: Mapped[str] = mapped_column(UUID(as_uuid=False), primary_key=True, default=_uuid)
    project_id: Mapped[str] = mapped_column(ForeignKey("projects.id"), nullable=False)
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id"), nullable=False)
    role: Mapped[str] = mapped_column(String(50), default="member")
    project: Mapped[Project] = relationship(back_populates="members")
    user: Mapped[User] = relationship(back_populates="projects")


class Finding(Base):
    __tablename__ = "findings"
    id: Mapped[str] = mapped_column(UUID(as_uuid=False), primary_key=True, default=_uuid)
    project_id: Mapped[str] = mapped_column(ForeignKey("projects.id"), nullable=False, index=True)
    source: Mapped[str] = mapped_column(String(100), nullable=False)
    source_id: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)
    source_tool: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    title: Mapped[str] = mapped_column(String(1000), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    finding_type: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)
    category: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    severity: Mapped[str] = mapped_column(String(50), nullable=False, index=True)
    cvss_score: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    cvss_vector: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)
    cve_ids: Mapped[Optional[list]] = mapped_column(JSON, default=list)
    risk_score: Mapped[Optional[float]] = mapped_column(Float, nullable=True, index=True)
    risk_label: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    asset_id: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)
    asset_type: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    asset_name: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)
    asset_region: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    asset_account_id: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    internet_facing: Mapped[bool] = mapped_column(Boolean, default=False)
    contains_sensitive_data: Mapped[bool] = mapped_column(Boolean, default=False)
    exploit_available: Mapped[bool] = mapped_column(Boolean, default=False)
    patch_available: Mapped[bool] = mapped_column(Boolean, default=False)
    remediation_text: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    references: Mapped[Optional[list]] = mapped_column(JSON, default=list)
    raw_data: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    status: Mapped[str] = mapped_column(String(50), default="open", index=True)
    first_seen: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    last_seen: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now(), index=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now(), onupdate=func.now())
    deleted_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    project: Mapped[Project] = relationship(back_populates="findings")
    translations: Mapped[list[Translation]] = relationship(back_populates="finding")


class Translation(Base):
    __tablename__ = "translations"
    id: Mapped[str] = mapped_column(UUID(as_uuid=False), primary_key=True, default=_uuid)
    finding_id: Mapped[str] = mapped_column(ForeignKey("findings.id"), nullable=False, index=True)
    audience: Mapped[str] = mapped_column(String(100), nullable=False)
    executive_summary: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    technical_explanation: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    business_impact: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    threat_scenario: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    risk_rating: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    remediation_steps: Mapped[Optional[list]] = mapped_column(JSON, default=list)
    terraform_example: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    aws_cli_example: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    kubernetes_example: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    policy_recommendation: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    jira_ticket: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    servicenow_ticket: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    extra_fields: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    model_used: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    prompt_tokens: Mapped[int] = mapped_column(Integer, default=0)
    completion_tokens: Mapped[int] = mapped_column(Integer, default=0)
    generated_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())
    finding: Mapped[Finding] = relationship(back_populates="translations")


class AuditLog(Base):
    __tablename__ = "audit_logs"
    id: Mapped[str] = mapped_column(UUID(as_uuid=False), primary_key=True, default=_uuid)
    user_id: Mapped[Optional[str]] = mapped_column(ForeignKey("users.id"), nullable=True)
    action: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    resource_type: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    resource_id: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)
    details: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    ip_address: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    user_agent: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now(), index=True)
    user: Mapped[Optional[User]] = relationship(back_populates="audit_logs")
