from __future__ import annotations
from pathlib import Path
from typing import Optional, Any
import sys
sys.path.insert(0, str(Path(__file__).parent.parent.parent))
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from cli.src.engines.translation_engine import TranslationEngine
from cli.src.models.finding import AudienceMode, NormalizedFinding, AffectedAsset, Severity, FindingSource
from ..models.db import Finding, Translation
from ..config import get_settings

settings = get_settings()


def _db_finding_to_normalized(f: Finding) -> NormalizedFinding:
    asset = None
    if f.asset_id:
        asset = AffectedAsset(
            resource_id=f.asset_id,
            resource_type=f.asset_type or "Unknown",
            resource_name=f.asset_name,
            region=f.asset_region,
            account_id=f.asset_account_id,
            internet_facing=f.internet_facing,
            contains_sensitive_data=f.contains_sensitive_data,
        )
    return NormalizedFinding(
        id=f.id,
        source=FindingSource(f.source),
        source_id=f.source_id,
        source_tool=f.source_tool,
        title=f.title,
        description=f.description or "",
        finding_type=f.finding_type,
        severity=Severity(f.severity),
        cve_ids=f.cve_ids or [],
        affected_asset=asset,
        exploit_available=f.exploit_available,
        patch_available=f.patch_available,
        remediation_text=f.remediation_text,
        references=f.references or [],
        risk_score=f.risk_score,
        raw_data=f.raw_data or {},
    )


async def get_or_create_translation(
    finding_id: str,
    audience: str,
    db: AsyncSession,
    context: Optional[dict[str, Any]] = None,
    force_refresh: bool = False,
    user_api_key: Optional[str] = None,
) -> Translation:
    if not force_refresh:
        existing = await db.execute(
            select(Translation).where(
                Translation.finding_id == finding_id,
                Translation.audience == audience,
            )
        )
        cached = existing.scalar_one_or_none()
        if cached:
            return cached

    result = await db.execute(select(Finding).where(Finding.id == finding_id))
    finding_row = result.scalar_one_or_none()
    if not finding_row:
        raise ValueError(f"Finding {finding_id} not found")

    nf = _db_finding_to_normalized(finding_row)

    api_key = user_api_key or settings.gemini_api_key or settings.anthropic_api_key
    if not api_key:
        raise ValueError("No API key available. Add your free Gemini API key in Settings.")
    engine = TranslationEngine(
        api_key=api_key,
        model=settings.translator_model,
        max_tokens=settings.translator_max_tokens,
    )
    t = engine.translate(nf, AudienceMode(audience), risk_score=finding_row.risk_score)

    db_translation = Translation(
        finding_id=finding_id,
        audience=audience,
        executive_summary=t.executive_summary,
        technical_explanation=t.technical_explanation,
        business_impact=t.business_impact,
        threat_scenario=t.threat_scenario,
        risk_rating=t.risk_rating,
        remediation_steps=t.remediation_steps,
        terraform_example=t.terraform_example,
        aws_cli_example=t.aws_cli_example,
        kubernetes_example=t.kubernetes_example,
        policy_recommendation=t.policy_recommendation,
        jira_ticket=t.jira_ticket,
        model_used=t.model_used,
        prompt_tokens=t.prompt_tokens,
        completion_tokens=t.completion_tokens,
    )

    if force_refresh:
        old = await db.execute(
            select(Translation).where(
                Translation.finding_id == finding_id,
                Translation.audience == audience,
            )
        )
        old_row = old.scalar_one_or_none()
        if old_row:
            await db.delete(old_row)

    db.add(db_translation)
    await db.flush()
    return db_translation
