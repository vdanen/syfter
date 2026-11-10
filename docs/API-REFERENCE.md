# Syfter API Reference

The Syfter API is served under `/api/v1`. For request and response schemas, query parameters, and a live “try it out” interface, open `/docs` on a running server. The OpenAPI document is available at `/openapi.json` and ReDoc at `/redoc`.

## Authentication

When authentication is enabled, send an API key with `X-API-Key`. If OIDC is configured, send a bearer token with `Authorization: Bearer <token>`. `/`, `/health`, `/docs`, `/openapi.json`, `/redoc`, and the `/dashboard` UI do not require API authentication. Admin endpoints require an admin key; endpoints with write access checks require a write or admin key.

See [Server Configuration](SERVER-CONFIGURATION.md) for authentication and OIDC settings.

## Endpoint groups

The list below is a route overview. The running OpenAPI docs are the source for exact schemas and parameters.

### Service

- `GET /` — service and backend information.
- `GET /health` — health check.

### Products and systems

- `GET|POST /api/v1/products/` — list or create products.
- `GET|PATCH|DELETE /api/v1/products/{product_name}/{product_version}` — read, update, or delete a product.
- `GET /api/v1/products/{product_name}/{product_version}/layers` — product layer summary.
- `GET /api/v1/products/{product_name}/{product_version}/attestations` — attestation metadata.
- `GET|POST /api/v1/systems/` — list or create systems.
- `GET|PUT|DELETE /api/v1/systems/{hostname}` — read, update, or delete a system.
- `GET /api/v1/systems/tags/` — list system tags.

### Scans and tags

- `GET /api/v1/scans/` and `GET /api/v1/scans/{scan_id}` — list scans or read a scan.
- `POST /api/v1/scans/upload` — upload scan results.
- `POST /api/v1/scans/import` — import an SPDX, CycloneDX, or syft-json SBOM.
- `POST /api/v1/scans/import-packages` — import a JSON or CSV package list.
- `DELETE /api/v1/scans/{scan_id}` — delete a scan.
- `GET /api/v1/scans/{scan_id}/tags`, `POST /api/v1/scans/{scan_id}/tags`, and `DELETE /api/v1/scans/{scan_id}/tags/{tag_name}` — manage tags on a scan.
- `GET /api/v1/tags/`, `PATCH /api/v1/tags/{tag_id}`, and `DELETE /api/v1/tags/{tag_id}` — list, rename, or delete tags.

### Queries and exports

- `GET /api/v1/query/stats` — catalog statistics.
- `GET /api/v1/query/packages` and `/api/v1/query/files` — search packages or files.
- `GET /api/v1/query/packages/frequency` — package version frequency.
- `GET /api/v1/query/dependencies` — search RPM dependencies.
- `GET /api/v1/query/components` — query component relationships.
- `GET /api/v1/query/provenance/{product_name}/{product_version}` and `/api/v1/query/trace` — trace package provenance across products.
- `GET /api/v1/query/list/packages/{product_name}/{product_version}` and `/api/v1/query/list/files/{product_name}/{product_version}` — list product contents.
- `GET /api/v1/query/systems/packages` and `/api/v1/query/systems/files` — query system inventories.
- `GET /api/v1/query/systems/list/packages/{hostname}` and `/api/v1/query/systems/list/files/{hostname}` — list a system’s packages or files.
- `GET /api/v1/export/{product_name}/{product_version}` and `/api/v1/export/{product_name}/{product_version}/url` — download an SBOM or retrieve a presigned URL.

### Container layers and relationships

- `GET /api/v1/layers/search/packages` — search packages by layer.
- `GET /api/v1/layers/chains` — list layer chains.
- `GET /api/v1/layers/{product_name}/{product_version}` — inspect a product’s layers.
- `GET /api/v1/layers/{product_name}/{product_version}/packages`, `/base-image`, and `/ancestry` — inspect layer packages and image lineage.
- `POST /api/v1/layers/enrich` — enrich layer metadata.
- `GET|POST /api/v1/relationships/` and `DELETE /api/v1/relationships/{relationship_id}` — list, create, or delete relationships.
- `POST /api/v1/relationships/backfill` — backfill relationships.

### VULCAN and administration

- `POST /api/v1/vulcan/analyze` — analyze CVE impact.
- `GET /api/v1/vulcan/analyses` and `GET /api/v1/vulcan/analyses/{analysis_id}` — list or read analyses.
- `POST /api/v1/vulcan/analyses/{analysis_id}/resolve` and `DELETE /api/v1/vulcan/analyses/{analysis_id}` — resolve or delete an analysis.
- `POST|GET /api/v1/admin/keys/` and `DELETE /api/v1/admin/keys/{key_id}` — create, list, or revoke API keys (admin only).
- `GET /api/v1/admin/access-log/` and `GET /api/v1/admin/access-log/summary` — review access logs (admin only).
