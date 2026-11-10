"""
Main FastAPI application — Syfter.
"""

import logging
import pathlib
import time

import uvicorn
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from .api import api_router
from .auth import auth_middleware, router as admin_router, access_log_router, seed_admin_key
from .config import get_config, ServerConfig
from .db import init_db
from .middleware import cache_middleware, rate_limit_middleware, access_log_middleware

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)

# Large SBOM uploads can be 500MB+ compressed
MAX_UPLOAD_SIZE = 1024 * 1024 * 1024  # 1GB

__version__ = "0.9.2.0"

app = FastAPI(
    title="Syfter API",
    description="SBOM platform for RPM and container image scanning at scale",
    version=__version__,
)

# Add CORS middleware for browser-based clients
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# Middleware execution order: access_log -> log -> auth -> rate_limit -> cache -> endpoint
# Starlette runs middleware in reverse registration order (last registered = outermost).

@app.middleware("http")
async def cache_middleware_handler(request: Request, call_next):
    """Response caching for slow endpoints (stats, products)."""
    return await cache_middleware(request, call_next)


@app.middleware("http")
async def rate_limit_middleware_handler(request: Request, call_next):
    """Per-key rate limiting (query: 60r/m, upload: 10r/m)."""
    return await rate_limit_middleware(request, call_next)


@app.middleware("http")
async def auth_middleware_handler(request: Request, call_next):
    """API key authentication."""
    return await auth_middleware(request, call_next)


@app.middleware("http")
async def log_requests(request: Request, call_next):
    """Log all incoming requests with timing."""
    start_time = time.time()

    content_length = request.headers.get("content-length", "unknown")
    team = getattr(request.state, "team_name", "-")
    logger.info(f"Request started: {request.method} {request.url.path} (size: {content_length})")

    try:
        response = await call_next(request)
        elapsed = time.time() - start_time
        logger.info(
            f"Request completed: {request.method} {request.url.path} -> "
            f"{response.status_code} ({elapsed:.2f}s)"
        )
        return response
    except Exception as e:
        elapsed = time.time() - start_time
        logger.error(
            f"Request failed: {request.method} {request.url.path} -> "
            f"{type(e).__name__}: {e} ({elapsed:.2f}s)"
        )
        raise


@app.middleware("http")
async def access_log_middleware_handler(request: Request, call_next):
    """Audit trail: log API requests to database."""
    return await access_log_middleware(request, call_next)


# Include API router
app.include_router(api_router, prefix="/api/v1")
app.include_router(admin_router, prefix="/api/v1")
app.include_router(access_log_router, prefix="/api/v1")

# Serve dashboard static files
_dashboard_dir = pathlib.Path(__file__).parent / "dashboard"
if _dashboard_dir.is_dir():
    app.mount("/dashboard", StaticFiles(directory=str(_dashboard_dir), html=True), name="dashboard")


@app.on_event("startup")
async def startup_event():
    """Initialize database and seed admin key on startup."""
    init_db()

    # Seed admin API key
    from .db.session import get_session_factory
    db = get_session_factory()()
    try:
        config = get_config()
        seed_admin_key(db, config.admin_api_key)
    finally:
        db.close()


@app.get("/")
def root():
    """Root endpoint with API info."""
    config = get_config()
    return {
        "name": "Syfter API",
        "version": __version__,
        "database": config.database.type,
        "storage": config.storage.type,
    }


@app.get("/health")
def health():
    """Health check endpoint."""
    return {"status": "healthy"}


def run_server():
    """Run the server (entry point for CLI)."""
    config = get_config()
    uvicorn.run(
        "server.main:app",
        host=config.host,
        port=config.port,
        reload=config.debug,
        workers=1 if config.debug else config.workers,
    )


if __name__ == "__main__":
    run_server()
