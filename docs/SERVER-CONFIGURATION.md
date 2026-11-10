# Server Configuration

Syfter reads server settings from environment variables at startup. For deployment examples and guidance on PostgreSQL, S3, and OpenShift, see the [Deployment Guide](DEPLOYMENT.md).

## Server process

| Variable | Default | Description |
|---|---:|---|
| `SYFTER_HOST` | `0.0.0.0` | Address the API server listens on. |
| `SYFTER_PORT` | `8000` | API server port. |
| `SYFTER_DEBUG` | `false` | Enable development reload behavior. |
| `SYFTER_WORKERS` | `4` | Number of Uvicorn worker processes outside debug mode. |
| `SYFTER_SKIP_FILE_INDEX_THRESHOLD` | `100000` | Skip file indexing for scans larger than this file count; set to `0` to disable the threshold. |

## Database

| Variable | Default | Description |
|---|---:|---|
| `SYFTER_DB_TYPE` | `sqlite` | Database backend: `sqlite` or `postgresql`. |
| `SYFTER_SQLITE_PATH` | `~/.syfter/syfter.db` | SQLite database file path. |
| `SYFTER_PG_HOST` | `localhost` | PostgreSQL host. |
| `SYFTER_PG_PORT` | `5432` | PostgreSQL port. |
| `SYFTER_PG_DATABASE` | `syfter` | PostgreSQL database name. |
| `SYFTER_PG_USER` | `syfter` | PostgreSQL user. |
| `SYFTER_PG_PASSWORD` | empty | PostgreSQL password. |

## SBOM storage

| Variable | Default | Description |
|---|---:|---|
| `SYFTER_STORAGE_TYPE` | `local` | Storage backend: `local` or `s3`. |
| `SYFTER_LOCAL_PATH` | `~/.syfter/sboms` | Directory used by local storage. |
| `SYFTER_S3_ENDPOINT` | unset | S3-compatible endpoint. Leave unset for AWS S3; set it for MinIO or another compatible service. |
| `SYFTER_S3_EXTERNAL_ENDPOINT` | unset | Public endpoint used to generate presigned URLs when the internal S3 endpoint is not reachable by clients. |
| `SYFTER_S3_BUCKET` | `syfter-sboms` | Bucket name. |
| `SYFTER_S3_ACCESS_KEY` | empty | S3 access key, when required. |
| `SYFTER_S3_SECRET_KEY` | empty | S3 secret key, when required. |
| `SYFTER_S3_REGION` | `us-east-1` | S3 region. |
| `SYFTER_S3_USE_SSL` | `true` | Use TLS when connecting to the S3 endpoint. |

## Authentication and access

| Variable | Default | Description |
|---|---:|---|
| `SYFTER_AUTH_ENABLED` | `true` | Require authentication for protected API routes. |
| `SYFTER_ADMIN_API_KEY` | unset | Initial admin key. If unset and no admin key exists, Syfter generates one and logs it once. |
| `SYFTER_AUTH_CACHE_TTL` | `60` | API key validation cache lifetime in seconds. |
| `SYFTER_OIDC_ISSUER_URL` | unset | OIDC issuer URL for bearer-token authentication. |
| `SYFTER_OIDC_CLIENT_ID` | `syfter-api` | Expected OIDC token audience/client ID. |
| `SYFTER_OIDC_JWKS_CACHE_TTL` | `3600` | OIDC signing-key cache lifetime in seconds. |
| `SYFTER_REQUIRE_CID_TAG` | `false` | Require an upload to include a tag beginning with `CID-`. |

Keep `SYFTER_AUTH_ENABLED` enabled in shared or production deployments. Store the initial admin key and S3 credentials in a secret manager or platform secret, not in source control.

## Rate limits and response cache

| Variable | Default | Description |
|---|---:|---|
| `SYFTER_RATE_LIMIT_ENABLED` | `true` | Enable per-key request limits. |
| `SYFTER_RATE_LIMIT_QUERY` | `60` | Query requests per minute per API key. |
| `SYFTER_RATE_LIMIT_QUERY_BURST` | `20` | Query burst allowance. |
| `SYFTER_RATE_LIMIT_UPLOAD` | `10` | Upload requests per minute per API key. |
| `SYFTER_RATE_LIMIT_UPLOAD_BURST` | `5` | Upload burst allowance. |
| `SYFTER_CACHE_ENABLED` | `true` | Enable response caching for supported endpoints. |
| `SYFTER_CACHE_STATS_TTL` | `300` | Statistics cache lifetime in seconds. |
| `SYFTER_CACHE_PRODUCTS_TTL` | `300` | Product-list cache lifetime in seconds. |

## CLI client

The CLI uses these environment variables to connect to a server:

| Variable | Default | Description |
|---|---|---|
| `SYFTER_SERVER` | unset | Base URL of the Syfter API server. |
| `SYFTER_API_KEY` | unset | API key sent with client requests. |
