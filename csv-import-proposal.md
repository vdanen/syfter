# CSV Import for Customer Package Lists

## Problem

We got our first customer "SBOM" and it's a CSV of packages, not SPDX/CycloneDX/syft-json. We need a way to ingest it without building a parallel import path.

## Approach: CSV-to-SBOM converter script

Rather than adding CSV support to the server or importing directly into DB tables, we'd add a `scan-csv.py` script alongside the existing scanners. It reads the CSV, builds a proper syft-format SBOM from the rows, and uploads through the normal `/api/v1/scans/upload` endpoint.

```bash
python3 scan-csv.py customer-packages.csv \
  --product "customer-app" --version "2024Q3" \
  --tags CID-0xdf3
```

## Why this way instead of direct DB import

- Tagging works exactly like every other scan — `--tags CID-0xdf3` on the command line, CID enforcement still applies
- S3 gets a real SBOM artifact (auditable, downloadable)
- No new API endpoints, no DB migration, no server changes
- Same dedup, stats refresh, and audit trail as any other upload
- CVE reporting via `cve_report.py` works immediately against the imported data

## First customer CSV — field mapping

The first CSV we received is a dependency risk assessment export with 13 fields. Here's how they map to syfter:

### Ingested fields

| CSV Field | Syfter Field | Notes |
|-----------|-------------|-------|
| `purl_canonical` | `purl` | Used directly — no PURL generation needed |
| `purl_type` | `type` | maven, npm, pypi, golang, etc. |
| `purl_name` | `name` | Package name |
| `current_version` / `version` | `version` | The version the customer is actually running |

### Preserved in S3 (not indexed in DB)

These fields don't map to syfter's package schema but contain useful supply chain health data. They're stored in each artifact's `metadata` dict inside the syft-format SBOM in S3 — no data loss, queryable later if we add columns.

| CSV Field | Description |
|-----------|-------------|
| `Priority` | Customer's priority ranking |
| `purl_namespace` | Already encoded in `purl_canonical` |
| `latest_version` | Latest available version (useful for drift analysis) |
| `current_version_release_date` | When the customer's version was released |
| `last_commit_at` | Last upstream commit date |
| `last_release_at` | Last upstream release date |
| `is_repo_archived` | Whether the upstream repo is archived |
| `relocation_type` | Package relocation info |
| `package_status` | Package lifecycle status |

### What gets generated automatically

- CPEs (for RPM-type packages, same logic as repodata scanner)
- A complete syft-format SBOM stored in S3
- Package index in PostgreSQL

## Handling future CSVs

The script won't be hardcoded to this one CSV format. It auto-detects columns by name and supports explicit mapping via CLI flags:

```bash
# Auto-detect: looks for purl_canonical, purl_name, current_version, etc.
python3 scan-csv.py packages.csv --product "app" --version "1.0" --tags CID-0xdf3

# Explicit mapping for CSVs with different headers
python3 scan-csv.py packages.csv --product "app" --version "1.0" \
  --col-name "Package Name" --col-version "Installed Version" \
  --col-purl "Package URL"
```

Minimum required columns: a package name and a version (or a full PURL that encodes both).

## What this doesn't solve

- Dependency/relationship data (CSVs won't have RPM requires/provides)
- File-level inventory (no file lists in a CSV)
- Layer attribution (not a container image)
- Queryable access to the supply chain health fields (Priority, archived status, etc.)

These are fine to leave empty — the server handles all of them as optional. The supply chain health fields can be promoted to DB columns in a future migration if they become valuable for VULCAN or CVE reporting.

## Effort

~half a day. It reuses `scanner_common.py` (upload logic) and the CPE/PURL generators already in `scan-repodata.py`. Standard library only (csv module), consistent with the other scanners.
