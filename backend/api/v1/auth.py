from fastapi import APIRouter, Depends, HTTPException, Request, status
from backend.main import limiter
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from ...database import get_db
from ...models.db import AuditLog, User
from ...models.schemas import TokenOut, UserCreate, UserLogin, UserOut, RefreshTokenIn
from ...services.auth import create_access_token, create_refresh_token, get_current_user, hash_password, verify_password
from ...config import get_settings
from jose import JWTError, jwt

settings = get_settings()
router = APIRouter(prefix="/auth", tags=["auth"])


@router.post("/register", response_model=UserOut, status_code=201)
@limiter.limit("3/minute")
async def register(request: Request, body: UserCreate, db: AsyncSession = Depends(get_db)):
    existing = (await db.execute(select(User).where(User.email == body.email))).scalar_one_or_none()
    if existing:
        raise HTTPException(status_code=400, detail="Email already registered")
    user = User(
        email=body.email,
        hashed_password=hash_password(body.password),
        full_name=body.full_name,
        role="analyst",
    )
    db.add(user)
    await db.flush()
    db.add(AuditLog(user_id=user.id, action="user.register", resource_type="user", resource_id=user.id))
    return user


DUMMY_HASH = hash_password("dummy-password-never-matches-xxxxxxxxxxxxxxxx")

@router.post("/login", response_model=TokenOut)
@limiter.limit("5/minute")
async def login(request: Request, body: UserLogin, db: AsyncSession = Depends(get_db)):
    user = (await db.execute(select(User).where(User.email == body.email))).scalar_one_or_none()
    hash_to_check = user.hashed_password if user else DUMMY_HASH
    password_valid = verify_password(body.password, hash_to_check)
    if not user or not password_valid or not user.is_active:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    db.add(AuditLog(
        user_id=user.id, action="user.login", resource_type="user", resource_id=user.id,
        ip_address=request.client.host if request.client else None,
    ))
    return TokenOut(
        access_token=create_access_token(user.id, user.role),
        refresh_token=create_refresh_token(user.id),
        expires_in=settings.access_token_expire_minutes * 60,
    )


@router.post("/refresh", response_model=TokenOut)
async def refresh(body: RefreshTokenIn, db: AsyncSession = Depends(get_db)):
    try:
        payload = jwt.decode(body.refresh_token, settings.secret_key, algorithms=[settings.algorithm])
        if payload.get("type") != "refresh":
            raise HTTPException(status_code=401, detail="Invalid token type")
        user_id = payload.get("sub")
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid refresh token")
    user = (await db.execute(select(User).where(User.id == user_id))).scalar_one_or_none()
    if not user or not user.is_active:
        raise HTTPException(status_code=401, detail="User not found")
    return TokenOut(
        access_token=create_access_token(user.id, user.role),
        refresh_token=create_refresh_token(user.id),
        expires_in=settings.access_token_expire_minutes * 60,
    )


@router.get("/me", response_model=UserOut)
async def me(current_user: User = Depends(get_current_user)):
    return current_user


@router.post("/demo", response_model=TokenOut)
@limiter.limit("10/minute")
async def demo_login(request: Request, db: AsyncSession = Depends(get_db)):
    """Shared demo account with pre-loaded findings. No registration required."""
    DEMO_EMAIL = "demo@sft.local"
    user = (await db.execute(select(User).where(User.email == DEMO_EMAIL))).scalar_one_or_none()
    if not user:
        user = User(
            email=DEMO_EMAIL,
            hashed_password=hash_password("demo-account-not-for-login-" + settings.secret_key[:8]),
            full_name="Demo User",
            role="viewer",
        )
        db.add(user)
        await db.flush()

    # Seed demo findings if none exist yet
    from ...services.finding_service import ingest_file, DEFAULT_PROJECT_ID
    from ...models.db import Finding
    from pathlib import Path as P
    count = (await db.execute(
        select(Finding).where(Finding.project_id == DEFAULT_PROJECT_ID).limit(1)
    )).scalar_one_or_none()
    if not count:
        examples_dir = P(__file__).parent.parent.parent.parent / "cli" / "examples"
        for fname in ["guardduty_findings.json", "security_hub_log4shell.json"]:
            fpath = examples_dir / fname
            if fpath.exists():
                try:
                    await ingest_file(fpath.read_bytes(), fname, DEFAULT_PROJECT_ID, db)
                except Exception:
                    pass

    return TokenOut(
        access_token=create_access_token(user.id, user.role),
        refresh_token=create_refresh_token(user.id),
        expires_in=settings.access_token_expire_minutes * 60,
    )
