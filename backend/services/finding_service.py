from __future__ import annotations
import json
import os
import uuid
from pathlib import Path
from typing import Optional
from sqlalchemy import func, select, text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
import sys
sys.path.insert(0, str(Path(__file__).parent.parent.parent))
from cli.src.parsers.base import ParserFactory
from cli.src.engines.risk_engine import score_finding
from ..models.db import Finding, Project
from ..config import get_settings
import logging

logger = logging.getLogger(__name__)
settings = get_settings()


async def ensure_project(project_id: str, db: AsyncSession):
    result = await db.execute(select(Project).where(Project.id == project_id))
    project = result.scalar_one_or_none()
    if not project:
        dummy_user_id = str(uuid.uuid4())
        await db.execute(
            text("""INSERT INTO users (id, email, hashed_password, full_name, role, is_active, mfa_enabled)
                    VALUES (:id, :email, :hp, :fn, :role, true, false)
                    ON CONFLICT (email) DO NOTHING"""),
            {"id": dummy_user_id, "email": "system@sft.local", "hp": "x", "fn": "System", "role": "admin"}
        )
        await db.flush()
        user_result = await db.execute(
            text("SELECT id FROM users WHERE email = 'system@sft.local' LIMIT 1")
        )
        real_user_id = user_result.scalar()
        new_project = Project(
            id=project_id,
            name="Default Project",
            description="Auto-created default project",
            created_by=real_user_id,
        )
        db.add(new_project)
        await db.flush()
        logger.info(f"Created default project {project_id}")


async def ingest_file(file_content: bytes, filename: str, project_id: str, db: AsyncSession) -> dict:
    try:
        await ensure_project(project_id, db)
    except Exception as e:
        logger.error(f"ensure_project failed: {e}", exc_info=True)
        raise

    os.makedirs(settings.upload_dir, exist_ok=True)
    ext = Path(filename).suffix.lower()
    tmp_path = Path(settings.upload_dir) / f"{uuid.uuid4()}{ext}"
    tmp_path.write_bytes(file_content)
    try:
        parsed = ParserFactory.from_file(tmp_path)
        logger.info(f"Parsed {len(parsed)} findings from {filename}")
    except Exception as e:
        logger.error(f"Parser failed: {e}", exc_info=True)
        tmp_path.unlink(missing_ok=True)
        raise
    finally:
        tmp_path.unlink(missing_ok=True)

    saved, failed = 0, 0
    for nf in parsed:
        try:
            risk_result = score_finding(nf)
            await _upsert_finding(nf, risk_result, project_id, db)
            saved += 1
            logger.info(f"Saved finding: {nf.title}")
        except Exception as e:
            logger.error(f"Failed to save finding '{nf.title}': {e}", exc_info=True)
            failed += 1

    await db.flush()
    logger.info(f"Upload complete: {saved} saved, {failed} failed")
    return {"total": len(parsed), "saved": saved, "failed": failed}


async def _upsert_finding(nf, risk_result, project_id: str, db: AsyncSession):
    existing = None
    if nf.source_id:
        result = await db.execute(
            select(Finding).where(Finding.project_id == project_id, Finding.source_id == nf.source_id)
        )
        existing = result.scalar_one_or_none()
    asset = nf.affected_asset
    data = dict(
        project_id=project_id,
        source=nf.source.value,
        source_id=nf.source_id,
        source_tool=nf.source_tool,
        title=nf.title,
        description=nf.description,
        finding_type=nf.finding_type,
        category=nf.category,
        severity=nf.severity.value,
        cvss_score=nf.cvss.base_score if nf.cvss else None,
        cvss_vector=nf.cvss.vector if nf.cvss else None,
        cve_ids=nf.cve_ids or [],
        risk_score=risk_result.composite_score,
        risk_label=risk_result.risk_label,
        epss_score=risk_result.epss_score,
        epss_percentile=risk_result.epss_percentile,
        in_kev=risk_result.in_kev,
        scoring_method=risk_result.scoring_method,
        risk_rationale=risk_result.risk_rationale,
        asset_id=asset.resource_id if asset else None,
        asset_type=asset.resource_type if asset else None,
        asset_name=asset.resource_name if asset else None,
        asset_region=asset.region if asset else None,
        asset_account_id=asset.account_id if asset else None,
        internet_facing=asset.internet_facing if asset else False,
        contains_sensitive_data=asset.contains_sensitive_data if asset else False,
        exploit_available=nf.exploit_available,
        patch_available=nf.patch_available,
        remediation_text=nf.remediation_text,
        references=nf.references or [],
        raw_data=nf.raw_data,
        first_seen=nf.first_seen.replace(tzinfo=None) if nf.first_seen else None,
        last_seen=nf.last_seen.replace(tzinfo=None) if nf.last_seen else None,
    )
    if existing:
        for k, v in data.items():
            setattr(existing, k, v)
    else:
        db.add(Finding(**data))


async def get_findings(
    project_id: str, db: AsyncSession,
    severity: Optional[str] = None, status: Optional[str] = None,
    source: Optional[str] = None, page: int = 1, page_size: int = 25,
) -> tuple[list[Finding], int]:
    q = select(Finding).where(Finding.project_id == project_id, Finding.deleted_at.is_(None))
    if severity:
        q = q.where(Finding.severity == severity.upper())
    if status:
        q = q.where(Finding.status == status)
    if source:
        q = q.where(Finding.source == source)
    total_q = select(func.count()).select_from(q.subquery())
    total = (await db.execute(total_q)).scalar_one()
    q = q.order_by(Finding.risk_score.desc().nulls_last()).offset((page - 1) * page_size).limit(page_size)
    rows = (await db.execute(q)).scalars().all()
    return rows, total


async def get_dashboard_stats(project_id: str, db: AsyncSession) -> dict:
    base = select(Finding).where(Finding.project_id == project_id, Finding.deleted_at.is_(None))
    total = (await db.execute(select(func.count()).select_from(base.subquery()))).scalar_one()
    open_q = base.where(Finding.status == "open")
    open_count = (await db.execute(select(func.count()).select_from(open_q.subquery()))).scalar_one()
    sev_rows = (await db.execute(
        select(Finding.severity, func.count()).where(
            Finding.project_id == project_id, Finding.deleted_at.is_(None)
        ).group_by(Finding.severity)
    )).all()
    sev_map = {r[0]: r[1] for r in sev_rows}
    avg_risk = (await db.execute(
        select(func.avg(Finding.risk_score)).where(Finding.project_id == project_id)
    )).scalar_one() or 0.0
    top_q = base.where(Finding.status == "open").order_by(Finding.risk_score.desc().nulls_last()).limit(5)
    top_findings = (await db.execute(top_q)).scalars().all()
    return {
        "total_findings": total,
        "open_findings": open_count,
        "critical_count": sev_map.get("CRITICAL", 0),
        "high_count": sev_map.get("HIGH", 0),
        "medium_count": sev_map.get("MEDIUM", 0),
        "low_count": sev_map.get("LOW", 0),
        "resolved_this_week": 0,
        "avg_risk_score": round(float(avg_risk), 2),
        "severity_breakdown": [{"severity": k, "count": v} for k, v in sev_map.items()],
        "top_findings": top_findings,
    }


DEFAULT_PROJECT_ID = '00000000-0000-0000-0000-000000000001'

async def verify_project_access(project_id: str, user_id: str, db: AsyncSession) -> bool:
    from ..models.db import Project
    # Default project is accessible to all authenticated users
    if project_id == DEFAULT_PROJECT_ID:
        result = await db.execute(select(Project).where(Project.id == project_id))
        return result.scalar_one_or_none() is not None
    # For other projects check ownership or membership
    result = await db.execute(
        select(Project).where(Project.id == project_id)
    )
    project = result.scalar_one_or_none()
    if not project:
        return False
    if project.created_by == user_id:
        return True
    from ..models.db import ProjectMember
    member = await db.execute(
        select(ProjectMember).where(
            ProjectMember.project_id == project_id,
            ProjectMember.user_id == user_id
        )
    )
    return member.scalar_one_or_none() is not None
