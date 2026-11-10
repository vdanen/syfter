# Syfter


[![OpenSSF Best Practices](https://www.bestpractices.dev/projects/11827/badge)](https://www.bestpractices.dev/projects/11827)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/vdanen/syfter/badge)](https://scorecard.dev/viewer/?uri=github.com/vdanen/syfter)
![GitHub release (latest SemVer)](https://img.shields.io/github/v/release/vdanen/syfter?sort=semver)
![PyPI release](https://img.shields.io/pypi/s/syfter)
![Downloads](https://static.pepy.tech/badge/syfter)

SBOM generation and management tool using [Syft](https://github.com/anchore/syft), designed for multi-team, large-scale SBOM management. Syfter provides authentication, rate limiting, response caching, recursive SBOM extraction, dependency graph parsing, RPM dependency tracking, cross-product tracing, container attestation indexing, and optimized queries for catalogs with more than 20 million packages.

## Features

- **SBOM collection and import:** Scan local targets and containers, or import SPDX 2.x, CycloneDX 1.x, syft-json, and JSON or CSV package lists.
- **SBOM enrichment:** Add product metadata, recursively extract nested components, parse dependency graphs, and index attestations.
- **Package and dependency search:** Filter by product, ecosystem, tag, or dependency; inspect package frequency and trace components across products and container layers.
- **VULCAN analysis:** Assess CVE impact across products and container layers, with tracker recommendations.
- **Organization and access controls:** Group scans with tags, optionally enforce `CID-` tags, authenticate with API keys or OIDC, and manage role-based access.
- **Operational controls:** Apply per-key rate limits, cache query responses, and record access logs.
- **Web dashboard:** Browse products, packages, statistics, and SBOM imports in a browser.
- **Scanning and relationship tools:** Scan containers, repository metadata, and SBOMer inventories; manage product-to-product component relationships.

The server is optimized for large catalogs. Representative production measurements include package searches completing in about 0.2 seconds, product listings in about 0.4 seconds, and statistics in under 100 milliseconds.

## Current Scale

Tested in production with:
- 20.8 million packages
- 504 million RPM dependency relationships
- 7,557 products (RPM repos + container images + middleware)
- 1,038 cosign attestation records
- All query endpoints < 2 seconds

## Installation

### Using uv (recommended)

```bash
# Install as a standalone CLI tool (isolated environment)
uv tool install syfter

# Or install with server components
uv tool install "syfter[server]"

# Upgrade to latest version
uv tool upgrade syfter
```

### Using pip

```bash
# Install from PyPI
pip install syfter

# Install with server components
pip install "syfter[server]"
```

### From Source

```bash
git clone https://github.com/vdanen/syfter.git
cd syfter

# Using uv
uv tool install .

# Or using pip
pip install -e .

# Install with all components (server + dev tools)
pip install -e ".[all]"
```

See [docs/BUILDING.md](docs/BUILDING.md) for detailed build and distribution options.

### Verify

```bash
syfter --version
```

If `syfter` is not found, ensure `~/.local/bin` is in your PATH:

```bash
export PATH="$HOME/.local/bin:$PATH"
```

> **Note:** Use Syfter 0.9.2.0 or newer to access the features described here. Check the installed version with `syfter --version`.

## Configure

Set two environment variables and you're ready to go:

```bash
export SYFTER_SERVER=https://your-server.example.com
export SYFTER_API_KEY=your-api-key
```

Verify:

```bash
syfter stats
```

## CLI Usage

```bash
# Search for packages (% is a wildcard)
syfter query -n "openssl%"
syfter query -n "curl%" -p rhel -v 10.0 --json

# List products
syfter products

# List packages in a product
syfter list -p rhel -v 10.0 -t packages

# Trace a package across the product stack (RHEL -> UBI -> layered containers)
syfter trace openssl-libs

# Query RPM dependencies
syfter deps openssl-libs                          # what requires openssl-libs?
syfter deps --package curl --type requires        # what does curl require?
syfter deps openssl-libs -p rhel -v 9.6           # scoped to a product

# Import an SBOM (SPDX, CycloneDX, or syft-json)
syfter import sbom.spdx.json -p myproduct -v 1.0
syfter import sbom.cdx.json -p myproduct -v 1.0 --tag CID-001

# Package version frequency analysis
syfter frequency openssl-libs

# Export SBOMs
syfter export -p rhel -v 10.0 -f spdx-json -o rhel.spdx.json
syfter export -p rhel -v 10.0 -f cyclonedx-json -o rhel.cdx.json

# Scan and upload
syfter scan /path/to/rpms -p rhel -v 10.1

# Component relationships
syfter relationships

# Check CVE exposure
syfter vulns -p ubi9 -v 9.7

# Delete a product
syfter delete -p myproduct -v 1.0
```

For full command help: `syfter --help` or `syfter <command> --help`.

## Server Quick Start

```bash
# Start the server
SYFTER_AUTH_ENABLED=true \
SYFTER_ADMIN_API_KEY=$(python3 -c "import secrets; print(secrets.token_hex(32))") \
SYFTER_DB_TYPE=postgresql \
SYFTER_PG_HOST=localhost \
SYFTER_PG_PASSWORD=changeme \
python -m uvicorn server.main:app --host 0.0.0.0 --port 8000

# Health check (no auth required)
curl http://localhost:8000/health

# Create a team key
curl -X POST http://localhost:8000/api/v1/admin/keys/ \
  -H "X-API-Key: $SYFTER_ADMIN_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"team_name": "security"}'
```

## API Endpoints

All endpoints require API key authentication via `X-API-Key` header except `/health`.

### Query
- `GET /health` -- Health check (no auth)
- `GET /api/v1/query/stats` -- Database statistics (cached)
- `GET /api/v1/query/packages?name=<pattern>` -- Package search (LIKE patterns)
- `GET /api/v1/query/dependencies?package_name=&dependency_type=` -- RPM dependency search
- `GET /api/v1/query/provenance/{product}/{version}?package_name=` -- Cross-product provenance
- `GET /api/v1/products` -- Product listing (paginated, cached)

### Container Layers
- `GET /api/v1/layers/{product}/{version}` -- Layer chain for a container
- `GET /api/v1/layers/{product}/{version}/packages?layer_type=base` -- Packages by layer
- `GET /api/v1/layers/{product}/{version}/base-image` -- Base image identification
- `POST /api/v1/layers/enrich` -- Batch layer enrichment

### Attestations
- `GET /api/v1/products/{product}/{version}/attestations` -- Cosign attestation metadata

### Relationships
- `GET /api/v1/relationships/` -- List component relationships
- `POST /api/v1/relationships/` -- Create relationship
- `DELETE /api/v1/relationships/{id}` -- Delete relationship

### Admin
- `POST /api/v1/admin/keys/` -- Create API key
- `GET /api/v1/admin/keys/` -- List API keys
- `DELETE /api/v1/admin/keys/{id}` -- Revoke API key

### VULCAN (CVE Impact Analysis)
- `POST /api/v1/vulcan/analyze` -- Analyze CVE impact across component and layer boundaries
- `GET /api/v1/vulcan/analyses` -- List stored analyses (filter by status, CVE, component)
- `GET /api/v1/vulcan/analyses/{id}` -- Get analysis with full tracker detail
- `POST /api/v1/vulcan/analyses/{id}/resolve` -- Mark analysis resolved
- `DELETE /api/v1/vulcan/analyses/{id}` -- Delete analysis

### Tags
- `GET /api/v1/tags` -- List all tags with scan counts
- `DELETE /api/v1/tags/{id}` -- Delete a tag
- `GET /api/v1/scans/{id}/tags` -- List tags on a scan
- `POST /api/v1/scans/{id}/tags` -- Add tags to a scan
- `DELETE /api/v1/scans/{id}/tags/{tag_name}` -- Remove a tag

### Upload
- `POST /api/v1/scans/upload` -- Upload scan results (multipart, supports `dependencies_json`, `image_layers_json`, `attestation_json`, `tags`)
- `POST /api/v1/scans/import` -- Import SBOM in any supported format (SPDX 2.x, CycloneDX 1.x, syft-json)
- `POST /api/v1/scans/import-packages` -- Import a plain package list (JSON array or CSV)

## Configuration

Additional server settings are configured through environment variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `SYFTER_AUTH_ENABLED` | `true` | Enable API key authentication |
| `SYFTER_ADMIN_API_KEY` | -- | Seed key for initial admin access |
| `SYFTER_AUTH_CACHE_TTL` | `60` | Auth validation cache TTL (seconds) |
| `SYFTER_RATE_LIMIT_ENABLED` | `true` | Enable per-key rate limiting |
| `SYFTER_RATE_LIMIT_QUERY` | `60` | Query requests per minute per key |
| `SYFTER_RATE_LIMIT_QUERY_BURST` | `20` | Query burst allowance |
| `SYFTER_RATE_LIMIT_UPLOAD` | `10` | Upload requests per minute per key |
| `SYFTER_RATE_LIMIT_UPLOAD_BURST` | `5` | Upload burst allowance |
| `SYFTER_CACHE_STATS_TTL` | `300` | Stats cache TTL (seconds) |
| `SYFTER_CACHE_PRODUCTS_TTL` | `300` | Products cache TTL (seconds) |
| `SYFTER_OIDC_ISSUER_URL` | -- | OIDC issuer URL for bearer token auth (e.g. Keycloak realm) |
| `SYFTER_OIDC_CLIENT_ID` | `syfter-api` | OIDC client ID for token validation |
| `SYFTER_REQUIRE_CID_TAG` | `false` | Require at least one `CID-` prefixed tag on upload |
| `SYFTER_SKIP_FILE_INDEX_THRESHOLD` | `100000` | Auto-skip file indexing above this package count |

Set `SYFTER_AUTH_ENABLED=false` for local development without keys.

## Database Indexes

For large-scale deployments (1M+ packages), these indexes are critical:

```sql
-- LIKE prefix queries + ORDER BY (the COLLATE "C" is essential)
CREATE INDEX idx_package_name_c ON packages (name COLLATE "C");

-- LIKE via text_pattern_ops (used by the index scan filter)
CREATE INDEX idx_package_name_pattern ON packages (name text_pattern_ops);

-- Foreign key lookups for product-scoped counts
CREATE INDEX idx_packages_product_id ON packages (product_id);
CREATE INDEX idx_scan_product ON scans (product_id);

-- Dependency queries (package-scoped + type filter)
CREATE INDEX idx_dep_package_type ON dependencies (package_id, dependency_type);
```

## Deployment

Syfter is designed for OpenShift/Kubernetes. The container image is built from `podman/Containerfile`.

A typical deployment includes:
- Syfter API (Deployment with oauth2-proxy sidecar for browser OIDC)
- PostgreSQL (StatefulSet)
- Keycloak (OIDC provider for browser access)
- AWS S3 via IRSA (SBOM object storage)

## License

Apache License 2.0

