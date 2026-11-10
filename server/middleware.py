"""
Rate limiting, response caching, and access logging middleware.

Replaces the nginx gateway's rate limiting (limit_req_zone) and
response caching (proxy_cache) with application-level equivalents,
allowing the nginx sidecar to be removed entirely.
"""

import collections
import logging
import threading
import time
from typing import Optional

from fastapi import Request
from fastapi.responses import JSONResponse, Response

logger = logging.getLogger(__name__)


# ============================================================================
# Token Bucket Rate Limiter
# ============================================================================


class _TokenBucket:
    """Thread-safe token bucket."""

    __slots__ = ("rate", "burst", "tokens", "last_time", "lock")

    def __init__(self, rate_per_minute: float, burst: int):
        self.rate = rate_per_minute / 60.0  # tokens per second
        self.burst = float(burst)
        self.tokens = float(burst)
        self.last_time = time.monotonic()
        self.lock = threading.Lock()

    def allow(self) -> tuple[bool, float, float]:
        """Returns (allowed, remaining_tokens, retry_after_seconds)."""
        with self.lock:
            now = time.monotonic()
            elapsed = now - self.last_time
            self.last_time = now
            self.tokens = min(self.burst, self.tokens + elapsed * self.rate)
            if self.tokens >= 1.0:
                self.tokens -= 1.0
                return True, self.tokens, 0.0
            retry_after = (1.0 - self.tokens) / self.rate if self.rate > 0 else 60.0
            return False, 0.0, retry_after


class RateLimiter:
    """Per-key rate limiter with zone-based limits."""

    def __init__(self):
        self._buckets: dict[str, _TokenBucket] = {}
        self._lock = threading.Lock()
        self._last_cleanup = time.monotonic()

    def check(
        self, key: str, zone: str, rate_per_minute: int, burst: int
    ) -> tuple[bool, int, int, float]:
        """Check rate limit. Returns (allowed, limit, remaining, retry_after)."""
        bucket_key = f"{zone}:{key}"
        with self._lock:
            now = time.monotonic()
            if now - self._last_cleanup > 300:
                self._cleanup(now)
                self._last_cleanup = now
            bucket = self._buckets.get(bucket_key)
            if not bucket:
                bucket = _TokenBucket(rate_per_minute, burst)
                self._buckets[bucket_key] = bucket
        allowed, remaining, retry_after = bucket.allow()
        return allowed, rate_per_minute, int(remaining), retry_after

    def _cleanup(self, now: float):
        """Remove stale buckets (unused for 10+ minutes)."""
        stale = [k for k, b in self._buckets.items() if now - b.last_time > 600]
        for k in stale:
            del self._buckets[k]


_rate_limiter = RateLimiter()


async def rate_limit_middleware(request: Request, call_next):
    """Per-key rate limiting. Mirrors nginx limit_req_zone behavior."""
    from .config import get_config

    config = get_config()

    if not config.auth_enabled or not config.rate_limit_enabled:
        return await call_next(request)

    # Only rate limit API paths
    if not request.url.path.startswith("/api/v1/"):
        return await call_next(request)

    # Use API key as rate limit key (auth middleware runs first)
    api_key = request.headers.get("X-API-Key", "")
    if not api_key:
        return await call_next(request)

    # Determine zone and limits
    if request.url.path == "/api/v1/scans/upload":
        zone = "upload"
        rate = config.rate_limit_upload
        burst = config.rate_limit_upload_burst
    else:
        zone = "query"
        rate = config.rate_limit_query
        burst = config.rate_limit_query_burst

    allowed, limit, remaining, retry_after = _rate_limiter.check(
        api_key, zone, rate, burst
    )

    if not allowed:
        return JSONResponse(
            status_code=429,
            content={
                "error": "Rate limit exceeded",
                "retry_after": round(retry_after, 1),
            },
            headers={
                "X-RateLimit-Limit": str(limit),
                "X-RateLimit-Remaining": "0",
                "Retry-After": str(int(retry_after) + 1),
            },
        )

    response = await call_next(request)
    response.headers["X-RateLimit-Limit"] = str(limit)
    response.headers["X-RateLimit-Remaining"] = str(remaining)
    return response


# ============================================================================
# Response Cache
# ============================================================================

_response_cache: dict[str, dict] = {}
_CACHE_MAX_ENTRIES = 100


def invalidate_response_cache(path_prefix: Optional[str] = None):
    """Clear cached responses. If path_prefix given, only matching entries."""
    if path_prefix is None:
        _response_cache.clear()
        return
    to_delete = [k for k in _response_cache if k.startswith(path_prefix)]
    for k in to_delete:
        del _response_cache[k]


def _get_cache_ttl(path: str) -> Optional[int]:
    """Get cache TTL for a path, or None if not cacheable."""
    from .config import get_config

    config = get_config()
    if path == "/api/v1/query/stats":
        return config.cache_stats_ttl
    if path in ("/api/v1/products", "/api/v1/products/"):
        return config.cache_products_ttl
    return None


async def cache_middleware(request: Request, call_next):
    """Response caching for slow endpoints. Replaces nginx proxy_cache."""
    from .config import get_config

    config = get_config()

    if not config.cache_enabled:
        return await call_next(request)

    # Auto-invalidate on mutations
    if request.method in ("POST", "PUT", "DELETE", "PATCH"):
        if request.url.path.startswith("/api/v1/scans"):
            invalidate_response_cache()  # full invalidation on scan changes
        elif request.url.path.startswith("/api/v1/products"):
            invalidate_response_cache("/api/v1/products")
        return await call_next(request)

    # Only cache GET requests
    if request.method != "GET":
        return await call_next(request)

    ttl = _get_cache_ttl(request.url.path)
    if ttl is None:
        return await call_next(request)

    # Cache key includes query params for paginated endpoints
    cache_key = request.url.path
    if request.url.query:
        cache_key = f"{request.url.path}?{request.url.query}"

    # Serve from cache if fresh
    cached = _response_cache.get(cache_key)
    if cached and (time.time() - cached["time"]) < ttl:
        return Response(
            content=cached["body"],
            status_code=cached["status"],
            media_type=cached["media_type"],
            headers={**cached.get("headers", {}), "X-Cache-Status": "HIT"},
        )

    # Call upstream
    response = await call_next(request)

    # Collect response body
    body = b""
    async for chunk in response.body_iterator:
        body += chunk if isinstance(chunk, bytes) else chunk.encode()

    # Cache successful responses
    if response.status_code == 200:
        if len(_response_cache) >= _CACHE_MAX_ENTRIES:
            oldest_key = min(_response_cache, key=lambda k: _response_cache[k]["time"])
            del _response_cache[oldest_key]
        _response_cache[cache_key] = {
            "time": time.time(),
            "body": body,
            "status": response.status_code,
            "media_type": response.media_type,
            "headers": {
                k: v
                for k, v in response.headers.items()
                if k.lower() not in ("content-length", "transfer-encoding")
            },
        }

    cache_status = "MISS"
    headers = dict(response.headers)
    headers["X-Cache-Status"] = cache_status

    return Response(
        content=body,
        status_code=response.status_code,
        media_type=response.media_type,
        headers=headers,
    )


# ============================================================================
# Access Log
# ============================================================================

_SKIP_LOG_PATHS = {"/health", "/docs", "/openapi.json", "/redoc"}
_log_queue = collections.deque(maxlen=5000)
_log_lock = threading.Lock()
_LOG_FLUSH_INTERVAL = 5  # seconds
_LOG_RETENTION_HOURS = 168  # 7 days


def _flush_access_log():
    """Flush queued log entries to the database."""
    from .db.session import get_session_factory
    from .db.models import AccessLog
    from datetime import datetime, timedelta

    while True:
        time.sleep(_LOG_FLUSH_INTERVAL)
        with _log_lock:
            if not _log_queue:
                continue
            entries = list(_log_queue)
            _log_queue.clear()

        try:
            SessionLocal = get_session_factory()
            db = SessionLocal()
            try:
                for entry in entries:
                    db.add(AccessLog(**entry))
                # Prune old entries
                cutoff = datetime.utcnow() - timedelta(hours=_LOG_RETENTION_HOURS)
                db.query(AccessLog).filter(AccessLog.timestamp < cutoff).delete()
                db.commit()
            finally:
                db.close()
        except Exception:
            logger.debug("Failed to flush access log", exc_info=True)


_flush_thread = threading.Thread(target=_flush_access_log, daemon=True)
_flush_started = False


async def access_log_middleware(request: Request, call_next):
    """Log API requests for audit trail."""
    global _flush_started
    if not _flush_started:
        _flush_thread.start()
        _flush_started = True

    if request.url.path in _SKIP_LOG_PATHS or request.url.path.startswith(("/dashboard", "/css", "/js")):
        return await call_next(request)

    start = time.monotonic()
    response = await call_next(request)
    elapsed_ms = int((time.monotonic() - start) * 1000)

    team_name = getattr(request.state, "team_name", None)
    key_prefix = None
    api_key = request.headers.get("X-API-Key", "")
    if api_key:
        key_prefix = api_key[:8]

    client_ip = request.client.host if request.client else None

    with _log_lock:
        _log_queue.append({
            "method": request.method,
            "path": request.url.path,
            "status_code": response.status_code,
            "response_ms": elapsed_ms,
            "key_prefix": key_prefix,
            "team_name": team_name,
            "client_ip": client_ip,
        })

    return response
