"""
API key authentication middleware and key management.
"""

import hashlib
import json
import logging
import os
import secrets
import time
import urllib.request
from datetime import datetime, timedelta
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from .db import get_db, ApiKey, AccessLog

logger = logging.getLogger(__name__)

# In-memory TTL cache for API key lookups
_key_cache: dict[str, tuple[float, dict]] = {}
_cache_ttl: int = 60  # seconds

# JWKS cache for OIDC Bearer token validation
_jwks_cache: dict = {}
_jwks_cache_time: float = 0


def _hash_key(api_key: str) -> str:
    """SHA-256 hash an API key."""
    return hashlib.sha256(api_key.encode()).hexdigest()


def _cache_get(key_hash: str) -> Optional[dict]:
    """Get a cached key lookup result."""
    entry = _key_cache.get(key_hash)
    if entry and (time.time() - entry[0]) < _cache_ttl:
        return entry[1]
    if entry:
        del _key_cache[key_hash]
    return None


def _cache_set(key_hash: str, data: dict):
    """Cache a key lookup result."""
    # Evict old entries if cache grows too large
    if len(_key_cache) > 256:
        cutoff = time.time() - _cache_ttl
        to_delete = [k for k, (t, _) in _key_cache.items() if t < cutoff]
        for k in to_delete:
            del _key_cache[k]
    _key_cache[key_hash] = (time.time(), data)


def _get_jwks(issuer_url: str, cache_ttl: int) -> dict:
    """Fetch and cache JWKS from the OIDC issuer."""
    global _jwks_cache, _jwks_cache_time
    if _jwks_cache and (time.time() - _jwks_cache_time) < cache_ttl:
        return _jwks_cache

    try:
        oidc_url = f"{issuer_url.rstrip('/')}/.well-known/openid-configuration"
        with urllib.request.urlopen(oidc_url, timeout=10) as resp:
            oidc_config = json.loads(resp.read())
        jwks_uri = oidc_config["jwks_uri"]
        with urllib.request.urlopen(jwks_uri, timeout=10) as resp:
            _jwks_cache = json.loads(resp.read())
        _jwks_cache_time = time.time()
        return _jwks_cache
    except Exception as e:
        logger.warning(f"Failed to fetch JWKS from {issuer_url}: {e}")
        return _jwks_cache  # return stale cache if available


def _validate_bearer_token(token: str) -> Optional[dict]:
    """Validate a Bearer JWT token against the configured OIDC issuer.

    Returns decoded claims dict on success, None on failure.
    """
    from .config import get_config
    config = get_config()

    if not config.oidc_issuer_url:
        return None

    try:
        import jwt
        from jwt import PyJWKClient

        jwks = _get_jwks(config.oidc_issuer_url, config.oidc_jwks_cache_ttl)
        if not jwks:
            return None

        jwk_client = PyJWKClient.__new__(PyJWKClient)
        jwk_client.jwk_set = jwt.PyJWKSet.from_dict(jwks)

        header = jwt.get_unverified_header(token)
        key = None
        for jwk in jwk_client.jwk_set.keys:
            if jwk.key_id == header.get("kid"):
                key = jwk.key
                break

        if not key:
            return None

        claims = jwt.decode(
            token,
            key,
            algorithms=["RS256"],
            audience=config.oidc_client_id,
            issuer=config.oidc_issuer_url,
        )
        return claims
    except Exception as e:
        logger.debug(f"Bearer token validation failed: {e}")
        return None


# Paths that skip authentication
SKIP_AUTH_PATHS = {"/", "/health", "/docs", "/openapi.json", "/redoc"}


async def auth_middleware(request: Request, call_next):
    """Validate API key on every request except health/docs."""
    from .config import get_config
    config = get_config()

    # Check if auth is enabled
    if not config.auth_enabled:
        request.state.team_name = "anonymous"
        request.state.api_key_id = None
        request.state.role = "admin"
        return await call_next(request)

    # Skip auth for exempt paths and dashboard static files
    if request.url.path in SKIP_AUTH_PATHS or request.url.path.startswith("/dashboard"):
        return await call_next(request)

    # Read API key from header
    api_key = request.headers.get("X-API-Key")

    # Check for Bearer token if no API key
    if not api_key:
        auth_header = request.headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            token = auth_header[7:]
            claims = _validate_bearer_token(token)
            if claims:
                username = claims.get("preferred_username") or claims.get("sub", "unknown")
                request.state.team_name = username
                request.state.api_key_id = None
                request.state.role = "write"
                return await call_next(request)
            return JSONResponse(
                status_code=401,
                content={"error": "Invalid or expired Bearer token"},
            )
        return JSONResponse(
            status_code=401,
            content={"error": "Missing API key or Bearer token", "hint": "Set X-API-Key header or Authorization: Bearer <token>"},
        )

    key_hash = _hash_key(api_key)

    # Check cache first
    cached = _cache_get(key_hash)
    if cached:
        if not cached.get("valid"):
            return JSONResponse(
                status_code=403,
                content={"error": "Invalid or expired API key"},
            )
        request.state.team_name = cached["team_name"]
        request.state.api_key_id = cached["id"]
        request.state.role = cached.get("role", "write")
        return await call_next(request)

    # Look up in database
    from .db.session import get_session_factory
    db = get_session_factory()()
    try:
        db_key = db.query(ApiKey).filter(ApiKey.key_hash == key_hash).first()

        if not db_key or not db_key.is_active:
            _cache_set(key_hash, {"valid": False})
            return JSONResponse(
                status_code=403,
                content={"error": "Invalid or expired API key"},
            )

        if db_key.expires_at and db_key.expires_at < datetime.utcnow():
            _cache_set(key_hash, {"valid": False})
            return JSONResponse(
                status_code=403,
                content={"error": "API key has expired"},
            )

        # Update last_used_at (non-blocking, best effort)
        db_key.last_used_at = datetime.utcnow()
        db.commit()

        role = getattr(db_key, "role", None) or ("admin" if db_key.is_admin else "write")
        _cache_set(key_hash, {
            "valid": True,
            "id": db_key.id,
            "team_name": db_key.team_name,
            "is_admin": db_key.is_admin,
            "role": role,
        })

        request.state.team_name = db_key.team_name
        request.state.api_key_id = db_key.id
        request.state.role = role
    finally:
        db.close()

    return await call_next(request)


def require_admin(request: Request):
    """FastAPI dependency that requires an admin API key."""
    role = getattr(request.state, "role", None)
    if role == "admin":
        return
    raise HTTPException(status_code=403, detail="Admin API key required")


def require_write(request: Request):
    """FastAPI dependency that requires write (or admin) access."""
    role = getattr(request.state, "role", None)
    if role in ("write", "admin"):
        return
    raise HTTPException(status_code=403, detail="Write access required (your key is read-only)")


def seed_admin_key(db: Session, admin_key: Optional[str] = None):
    """Seed an admin API key if none exists."""
    existing = db.query(ApiKey).filter(ApiKey.is_admin == True).first()
    if existing:
        logger.info(f"Admin key already exists (prefix: {existing.key_prefix}...)")
        return

    if not admin_key:
        admin_key = os.environ.get("SYFTER_ADMIN_API_KEY")

    if not admin_key:
        admin_key = secrets.token_hex(32)
        logger.warning(f"No SYFTER_ADMIN_API_KEY set. Generated admin key: {admin_key}")
        logger.warning("Save this key — it will not be shown again.")

    key_hash = _hash_key(admin_key)
    db_key = ApiKey(
        key_hash=key_hash,
        key_prefix=admin_key[:8],
        team_name="admin",
        description="Auto-generated admin key",
        is_admin=True,
        role="admin",
    )
    db.add(db_key)
    db.commit()
    logger.info(f"Admin API key seeded (prefix: {admin_key[:8]}...)")


# --- Admin API key management endpoints ---

router = APIRouter(prefix="/admin/keys", tags=["admin"])


class ApiKeyCreateRequest(BaseModel):
    team_name: str = Field(..., description="Team name this key belongs to")
    description: Optional[str] = Field(default=None, description="Key description")
    expires_in_days: Optional[int] = Field(default=None, description="Days until expiration")
    role: str = Field(default="write", description="Key role: read, write, or admin")


class ApiKeyResponse(BaseModel):
    id: int
    key_prefix: str
    team_name: str
    description: Optional[str]
    is_active: bool
    is_admin: bool
    role: str = "write"
    created_at: datetime
    last_used_at: Optional[datetime]
    expires_at: Optional[datetime]

    class Config:
        from_attributes = True


class ApiKeyCreatedResponse(ApiKeyResponse):
    api_key: str  # Only returned once on creation


@router.post("/", response_model=ApiKeyCreatedResponse, status_code=201)
def create_api_key(
    body: ApiKeyCreateRequest,
    request: Request,
    admin=Depends(require_admin),
    db: Session = Depends(get_db),
):
    """Create a new API key. Returns the plaintext key exactly once."""
    if body.role not in ("read", "write", "admin"):
        raise HTTPException(status_code=400, detail="role must be read, write, or admin")

    api_key = secrets.token_hex(32)
    key_hash = _hash_key(api_key)

    expires_at = None
    if body.expires_in_days:
        expires_at = datetime.utcnow() + timedelta(days=body.expires_in_days)

    db_key = ApiKey(
        key_hash=key_hash,
        key_prefix=api_key[:8],
        team_name=body.team_name,
        description=body.description,
        expires_at=expires_at,
        role=body.role,
        is_admin=(body.role == "admin"),
    )
    db.add(db_key)
    db.commit()
    db.refresh(db_key)

    return ApiKeyCreatedResponse(
        id=db_key.id,
        key_prefix=db_key.key_prefix,
        team_name=db_key.team_name,
        description=db_key.description,
        is_active=db_key.is_active,
        is_admin=db_key.is_admin,
        role=db_key.role,
        created_at=db_key.created_at,
        last_used_at=db_key.last_used_at,
        expires_at=db_key.expires_at,
        api_key=api_key,
    )


@router.get("/", response_model=list[ApiKeyResponse])
def list_api_keys(
    request: Request,
    admin=Depends(require_admin),
    db: Session = Depends(get_db),
):
    """List all API keys (metadata only, no plaintext)."""
    keys = db.query(ApiKey).order_by(ApiKey.created_at).all()
    return [
        ApiKeyResponse(
            id=k.id,
            key_prefix=k.key_prefix,
            team_name=k.team_name,
            description=k.description,
            is_active=k.is_active,
            is_admin=k.is_admin,
            role=getattr(k, "role", "admin" if k.is_admin else "write"),
            created_at=k.created_at,
            last_used_at=k.last_used_at,
            expires_at=k.expires_at,
        )
        for k in keys
    ]


@router.delete("/{key_id}", status_code=204)
def revoke_api_key(
    key_id: int,
    request: Request,
    admin=Depends(require_admin),
    db: Session = Depends(get_db),
):
    """Revoke (deactivate) an API key."""
    db_key = db.query(ApiKey).filter(ApiKey.id == key_id).first()
    if not db_key:
        raise HTTPException(status_code=404, detail="API key not found")

    db_key.is_active = False
    db.commit()

    # Invalidate cache
    _key_cache.clear()


# --- Admin access log endpoints ---

access_log_router = APIRouter(prefix="/admin/access-log", tags=["admin"])


@access_log_router.get("/")
def get_access_log(
    request: Request,
    limit: int = 100,
    team: Optional[str] = None,
    admin=Depends(require_admin),
    db: Session = Depends(get_db),
):
    """Query recent API access log entries (admin only)."""
    query = db.query(AccessLog).order_by(AccessLog.timestamp.desc())
    if team:
        query = query.filter(AccessLog.team_name == team)
    rows = query.limit(limit).all()
    return [
        {
            "id": r.id,
            "timestamp": r.timestamp.isoformat() if r.timestamp else None,
            "method": r.method,
            "path": r.path,
            "status_code": r.status_code,
            "response_ms": r.response_ms,
            "key_prefix": r.key_prefix,
            "team_name": r.team_name,
            "client_ip": r.client_ip,
        }
        for r in rows
    ]


@access_log_router.get("/summary")
def get_access_log_summary(
    request: Request,
    admin=Depends(require_admin),
    db: Session = Depends(get_db),
):
    """Summarize access log by team (admin only)."""
    from sqlalchemy import func

    rows = (
        db.query(
            AccessLog.team_name,
            func.count(AccessLog.id).label("request_count"),
            func.avg(AccessLog.response_ms).label("avg_response_ms"),
            func.max(AccessLog.timestamp).label("last_request"),
        )
        .group_by(AccessLog.team_name)
        .order_by(func.count(AccessLog.id).desc())
        .all()
    )
    return [
        {
            "team_name": r.team_name,
            "request_count": r.request_count,
            "avg_response_ms": round(r.avg_response_ms) if r.avg_response_ms else 0,
            "last_request": r.last_request.isoformat() if r.last_request else None,
        }
        for r in rows
    ]
