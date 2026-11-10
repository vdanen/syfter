"""
Server configuration with environment variable support.
"""

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal, Optional


@dataclass
class DatabaseConfig:
    """Database configuration."""

    # Database type: sqlite or postgresql
    type: Literal["sqlite", "postgresql"] = "sqlite"

    # SQLite settings
    sqlite_path: Path = field(default_factory=lambda: Path("~/.syfter/syfter.db").expanduser())

    # PostgreSQL settings
    pg_host: str = "localhost"
    pg_port: int = 5432
    pg_database: str = "syfter"
    pg_user: str = "syfter"
    pg_password: str = ""

    @property
    def url(self) -> str:
        """Get SQLAlchemy database URL."""
        if self.type == "sqlite":
            self.sqlite_path.parent.mkdir(parents=True, exist_ok=True)
            return f"sqlite:///{self.sqlite_path}"
        else:
            return (
                f"postgresql://{self.pg_user}:{self.pg_password}"
                f"@{self.pg_host}:{self.pg_port}/{self.pg_database}"
            )

    @classmethod
    def from_env(cls) -> "DatabaseConfig":
        """Load configuration from environment variables."""
        db_type = os.getenv("SYFTER_DB_TYPE", "sqlite")

        if db_type == "postgresql":
            return cls(
                type="postgresql",
                pg_host=os.getenv("SYFTER_PG_HOST", "localhost"),
                pg_port=int(os.getenv("SYFTER_PG_PORT", "5432")),
                pg_database=os.getenv("SYFTER_PG_DATABASE", "syfter"),
                pg_user=os.getenv("SYFTER_PG_USER", "syfter"),
                pg_password=os.getenv("SYFTER_PG_PASSWORD", ""),
            )
        else:
            return cls(
                type="sqlite",
                sqlite_path=Path(
                    os.getenv("SYFTER_SQLITE_PATH", "~/.syfter/syfter.db")
                ).expanduser(),
            )


@dataclass
class StorageConfig:
    """Object storage configuration."""

    # Storage type: local or s3
    type: Literal["local", "s3"] = "local"

    # Local storage settings
    local_path: Path = field(default_factory=lambda: Path("~/.syfter/sboms").expanduser())

    # S3/MinIO settings
    s3_endpoint: Optional[str] = None  # None = AWS S3, set for MinIO
    s3_external_endpoint: Optional[str] = None  # External URL for presigned URLs (for clients outside container network)
    s3_bucket: str = "syfter-sboms"
    s3_access_key: str = ""
    s3_secret_key: str = ""
    s3_region: str = "us-east-1"
    s3_use_ssl: bool = True

    @classmethod
    def from_env(cls) -> "StorageConfig":
        """Load configuration from environment variables."""
        storage_type = os.getenv("SYFTER_STORAGE_TYPE", "local")

        if storage_type == "s3":
            return cls(
                type="s3",
                s3_endpoint=os.getenv("SYFTER_S3_ENDPOINT"),  # None for AWS S3
                s3_external_endpoint=os.getenv("SYFTER_S3_EXTERNAL_ENDPOINT"),  # For presigned URLs
                s3_bucket=os.getenv("SYFTER_S3_BUCKET", "syfter-sboms"),
                s3_access_key=os.getenv("SYFTER_S3_ACCESS_KEY", ""),
                s3_secret_key=os.getenv("SYFTER_S3_SECRET_KEY", ""),
                s3_region=os.getenv("SYFTER_S3_REGION", "us-east-1"),
                s3_use_ssl=os.getenv("SYFTER_S3_USE_SSL", "true").lower() == "true",
            )
        else:
            return cls(
                type="local",
                local_path=Path(
                    os.getenv("SYFTER_LOCAL_PATH", "~/.syfter/sboms")
                ).expanduser(),
            )


@dataclass
class ServerConfig:
    """Main server configuration."""

    host: str = "0.0.0.0"
    port: int = 8000
    debug: bool = False
    workers: int = 4
    # Skip file indexing for scans with more than this many files (0 = never skip)
    skip_file_index_threshold: int = 100000
    # Authentication
    auth_enabled: bool = True
    admin_api_key: Optional[str] = None
    auth_cache_ttl: int = 60
    # Rate limiting (per API key)
    rate_limit_enabled: bool = True
    rate_limit_query: int = 60         # requests per minute (all API endpoints)
    rate_limit_query_burst: int = 20
    rate_limit_upload: int = 10        # requests per minute (scan upload)
    rate_limit_upload_burst: int = 5
    # Response caching
    cache_enabled: bool = True
    cache_stats_ttl: int = 300         # seconds (5 minutes)
    cache_products_ttl: int = 300      # seconds (5 minutes)
    # OIDC (Keycloak) Bearer token auth (dual auth with API keys)
    oidc_issuer_url: Optional[str] = None  # e.g. https://keycloak.../realms/syfter
    oidc_client_id: str = "syfter-api"
    oidc_jwks_cache_ttl: int = 3600    # seconds (1 hour)
    # CID tag enforcement
    require_cid_tag: bool = False

    database: DatabaseConfig = field(default_factory=DatabaseConfig.from_env)
    storage: StorageConfig = field(default_factory=StorageConfig.from_env)

    @classmethod
    def from_env(cls) -> "ServerConfig":
        """Load configuration from environment variables."""
        return cls(
            host=os.getenv("SYFTER_HOST", "0.0.0.0"),
            port=int(os.getenv("SYFTER_PORT", "8000")),
            debug=os.getenv("SYFTER_DEBUG", "false").lower() == "true",
            workers=int(os.getenv("SYFTER_WORKERS", "4")),
            skip_file_index_threshold=int(os.getenv("SYFTER_SKIP_FILE_INDEX_THRESHOLD", "100000")),
            auth_enabled=os.getenv("SYFTER_AUTH_ENABLED", "true").lower() == "true",
            admin_api_key=os.getenv("SYFTER_ADMIN_API_KEY"),
            auth_cache_ttl=int(os.getenv("SYFTER_AUTH_CACHE_TTL", "60")),
            rate_limit_enabled=os.getenv("SYFTER_RATE_LIMIT_ENABLED", "true").lower() == "true",
            rate_limit_query=int(os.getenv("SYFTER_RATE_LIMIT_QUERY", "60")),
            rate_limit_query_burst=int(os.getenv("SYFTER_RATE_LIMIT_QUERY_BURST", "20")),
            rate_limit_upload=int(os.getenv("SYFTER_RATE_LIMIT_UPLOAD", "10")),
            rate_limit_upload_burst=int(os.getenv("SYFTER_RATE_LIMIT_UPLOAD_BURST", "5")),
            cache_enabled=os.getenv("SYFTER_CACHE_ENABLED", "true").lower() == "true",
            cache_stats_ttl=int(os.getenv("SYFTER_CACHE_STATS_TTL", "300")),
            cache_products_ttl=int(os.getenv("SYFTER_CACHE_PRODUCTS_TTL", "300")),
            oidc_issuer_url=os.getenv("SYFTER_OIDC_ISSUER_URL"),
            oidc_client_id=os.getenv("SYFTER_OIDC_CLIENT_ID", "syfter-api"),
            oidc_jwks_cache_ttl=int(os.getenv("SYFTER_OIDC_JWKS_CACHE_TTL", "3600")),
            require_cid_tag=os.getenv("SYFTER_REQUIRE_CID_TAG", "false").lower() == "true",
            database=DatabaseConfig.from_env(),
            storage=StorageConfig.from_env(),
        )


# Global config instance
_config: Optional[ServerConfig] = None


def get_config() -> ServerConfig:
    """Get the global configuration instance."""
    global _config
    if _config is None:
        _config = ServerConfig.from_env()
    return _config


def set_config(config: ServerConfig) -> None:
    """Set the global configuration instance."""
    global _config
    _config = config
