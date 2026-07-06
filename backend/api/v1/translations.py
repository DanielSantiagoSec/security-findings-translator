from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from ...database import get_db
from ...models.db import Translation, User
from ...models.schemas import BulkTranslateRequest, TranslateRequest, TranslationOut
from ...services.auth import get_current_user
from ...services.translation_service import get_or_create_translation

router = APIRouter(prefix="/translations", tags=["translations"])


@router.post("", response_model=TranslationOut, status_code=201)
async def translate_finding(
    body: TranslateRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    try:
        translation = await get_or_create_translation(
            finding_id=body.finding_id,
            audience=body.audience,
            db=db,
            context=body.context,
            user_api_key=body.api_key,
        )
        return translation
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Translation failed: {e}")


@router.post("/refresh", response_model=TranslationOut)
async def refresh_translation(
    body: TranslateRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    try:
        return await get_or_create_translation(
            finding_id=body.finding_id,
            audience=body.audience,
            db=db,
            force_refresh=True,
            user_api_key=body.api_key,
        )
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


@router.get("/{finding_id}", response_model=list[TranslationOut])
async def get_translations(
    finding_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    rows = (await db.execute(
        select(Translation).where(Translation.finding_id == finding_id)
    )).scalars().all()
    return rows


@router.post("/bulk", status_code=202)
async def bulk_translate(
    body: BulkTranslateRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    results = []
    for finding_id in body.finding_ids:
        for audience in body.audiences:
            try:
                await get_or_create_translation(finding_id, audience, db)
                results.append({"finding_id": finding_id, "audience": audience, "status": "ok"})
            except Exception as e:
                results.append({"finding_id": finding_id, "audience": audience, "status": "error", "error": str(e)})
    return {"results": results, "total": len(results)}
