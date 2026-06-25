from typing import Optional
from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from ...database import get_db
from ...models.db import Finding, User
from ...models.schemas import DashboardStats, FindingListOut, FindingOut, FindingStatusUpdate, UploadResult
from ...services.auth import get_current_user
from ...services.finding_service import get_dashboard_stats, get_findings, ingest_file
from ...config import get_settings
import uuid

settings = get_settings()
router = APIRouter(prefix="/findings", tags=["findings"])


@router.post("/upload", response_model=UploadResult, status_code=201)
async def upload_findings(
    file: UploadFile = File(...),
    project_id: str = Form(...),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    content = await file.read()
    if len(content) > settings.max_upload_size_mb * 1024 * 1024:
        raise HTTPException(status_code=413, detail="File too large")
    result = await ingest_file(content, file.filename or "upload.json", project_id, db)
    return UploadResult(
        upload_id=str(uuid.uuid4()),
        filename=file.filename or "upload.json",
        findings_count=result["total"],
        findings_parsed=result["saved"],
        findings_failed=result["failed"],
        project_id=project_id,
        status="complete",
    )


@router.get("", response_model=FindingListOut)
async def list_findings(
    project_id: str,
    severity: Optional[str] = None,
    status: Optional[str] = None,
    source: Optional[str] = None,
    page: int = 1,
    page_size: int = 25,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    findings, total = await get_findings(project_id, db, severity, status, source, page, page_size)
    return FindingListOut(findings=findings, total=total, page=page, page_size=page_size)


@router.get("/dashboard", response_model=DashboardStats)
async def dashboard(
    project_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    return await get_dashboard_stats(project_id, db)


@router.get("/{finding_id}", response_model=FindingOut)
async def get_finding(
    finding_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    row = (await db.execute(select(Finding).where(Finding.id == finding_id))).scalar_one_or_none()
    if not row:
        raise HTTPException(status_code=404, detail="Finding not found")
    return row


@router.patch("/{finding_id}/status", response_model=FindingOut)
async def update_status(
    finding_id: str,
    body: FindingStatusUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    row = (await db.execute(select(Finding).where(Finding.id == finding_id))).scalar_one_or_none()
    if not row:
        raise HTTPException(status_code=404, detail="Finding not found")
    row.status = body.status
    await db.flush()
    return row


@router.delete("/clear", status_code=200)
async def clear_findings(
    project_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    from sqlalchemy import delete
    from ...models.db import Translation
    finding_ids = (await db.execute(
        select(Finding.id).where(Finding.project_id == project_id)
    )).scalars().all()
    if finding_ids:
        await db.execute(delete(Translation).where(Translation.finding_id.in_(finding_ids)))
    await db.execute(delete(Finding).where(Finding.project_id == project_id))
    await db.flush()
    return {"message": "All findings cleared", "project_id": project_id}
