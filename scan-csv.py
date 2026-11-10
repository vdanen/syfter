#!/usr/bin/env python3
"""
scan-csv.py -- CSV package list importer for syfter.

Converts CSV package inventories (e.g., JFrog Catalog exports) into
syfter's package index format and uploads them. Designed for customer
package lists that aren't in standard SBOM formats.

Usage:
    # Dry-run (default) -- parse and show what would be uploaded
    python3 scan-csv.py packages.csv --product "customer-app" --version "2024Q3"

    # Upload to server
    python3 scan-csv.py packages.csv --product "customer-app" --version "2024Q3" --upload

    # With tagging
    python3 scan-csv.py packages.csv --product "customer-app" --version "2024Q3" \\
        --tags CID-0xdf3 --upload

    # Explicit column mapping for non-standard headers
    python3 scan-csv.py packages.csv --product "app" --version "1.0" \\
        --col-name "Package Name" --col-version "Installed Version"

Requires: SYFTER_SERVER and SYFTER_API_KEY environment variables (for --upload).
Dependencies: Python stdlib only + scanner_common.py.
"""

import argparse
import csv
import json
import logging
import os
import sys
import uuid
from collections import Counter

from scanner_common import upload_to_syfter

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
log = logging.getLogger("scan-csv")

PURL_TYPE_MAP = {
    "rpm": "rpm",
    "maven": "java",
    "npm": "npm",
    "pypi": "python",
    "golang": "go-module",
    "nuget": "nuget",
    "gem": "gem",
    "generic": "generic",
    "cargo": "rust",
    "composer": "php",
    "swift": "swift",
    "cocoapods": "cocoapods",
    "hex": "erlang",
    "pub": "dart",
}

COLUMN_ALIASES = {
    "name": ["purl_name", "name", "package_name", "pkg_name", "component",
             "package", "artifact_id", "artifactid"],
    "version": ["current_version", "version", "pkg_version", "installed_version",
                 "component_version"],
    "purl": ["purl_canonical", "purl", "package_url"],
    "type": ["purl_type", "type", "pkg_type", "package_type", "ecosystem"],
    "namespace": ["purl_namespace", "namespace", "group_id", "group", "scope"],
    "license": ["license", "license_id", "spdx_license"],
}

EXTRA_FIELDS = [
    "priority", "latest_version", "version_release_date",
    "last_commit_at", "last_release_at", "is_repo_archived",
    "relocation_type", "package_status",
]


def detect_columns(headers):
    """Auto-detect column mapping from CSV headers."""
    mapping = {}
    header_lower = {h.lower().strip(): h for h in headers}

    for field, aliases in COLUMN_ALIASES.items():
        for alias in aliases:
            if alias.lower() in header_lower:
                mapping[field] = header_lower[alias.lower()]
                break

    return mapping


def parse_purl(purl):
    """Parse a Package URL into (type, namespace, name, version, qualifiers)."""
    if not purl or ":" not in purl:
        return None, None, None, None, {}
    rest = purl.split(":", 1)[1]
    qualifiers = {}
    if "?" in rest:
        rest, qs = rest.split("?", 1)
        for pair in qs.split("&"):
            if "=" in pair:
                k, v = pair.split("=", 1)
                qualifiers[k] = v
    if "#" in rest:
        rest = rest.split("#", 1)[0]

    rest = rest.lstrip("/")
    parts = rest.split("/")
    pkg_type = parts[0] if parts else None

    name_ver = parts[-1] if len(parts) > 1 else parts[0]
    if "@" in name_ver:
        name_part, version = name_ver.rsplit("@", 1)
    else:
        name_part, version = name_ver, None

    if len(parts) >= 3:
        namespace = "/".join(parts[1:-1])
        name = name_part
    elif len(parts) == 2:
        namespace = None
        name = name_part
    else:
        namespace = None
        name = name_part

    return pkg_type, namespace, name, version, qualifiers


def build_purl(pkg_type, namespace, name, version):
    """Build a PURL string from components."""
    if namespace:
        return f"pkg:{pkg_type}/{namespace}/{name}@{version}"
    return f"pkg:{pkg_type}/{name}@{version}"


def read_csv(csv_path, col_overrides=None):
    """Read a CSV file and return parsed package entries.

    Returns (packages, extra_data, warnings) where:
      - packages: list of dicts with syfter-compatible fields
      - extra_data: dict mapping package index to extra CSV fields
      - warnings: list of warning strings
    """
    col_overrides = col_overrides or {}
    packages = []
    extra_data = {}
    warnings = []

    with open(csv_path, newline="", encoding="utf-8-sig") as f:
        reader = csv.DictReader(f)
        if not reader.fieldnames:
            raise ValueError("CSV file has no headers")

        mapping = detect_columns(reader.fieldnames)
        mapping.update({k: v for k, v in col_overrides.items() if v})
        log.info("Column mapping: %s", json.dumps(mapping, indent=2))

        missing = []
        has_purl = "purl" in mapping
        if not has_purl:
            if "name" not in mapping:
                missing.append("name")
            if "version" not in mapping:
                missing.append("version")
        if missing:
            raise ValueError(
                f"Cannot detect required columns: {', '.join(missing)}. "
                f"Available: {', '.join(reader.fieldnames)}. "
                f"Use --col-name / --col-version to specify."
            )

        for row_num, row in enumerate(reader, start=2):
            purl_raw = row.get(mapping.get("purl", ""), "").strip()
            name = row.get(mapping.get("name", ""), "").strip()
            version = row.get(mapping.get("version", ""), "").strip()
            pkg_type = row.get(mapping.get("type", ""), "").strip().lower()
            namespace = row.get(mapping.get("namespace", ""), "").strip()
            license_val = row.get(mapping.get("license", ""), "").strip()

            if purl_raw:
                p_type, p_ns, p_name, p_ver, p_quals = parse_purl(purl_raw)
                if not name:
                    name = p_name or ""
                if not pkg_type:
                    pkg_type = p_type or ""
                if not namespace:
                    namespace = p_ns or ""
            else:
                p_type, p_ns, p_name, p_ver, p_quals = None, None, None, None, {}

            if not name:
                warnings.append(f"Row {row_num}: skipped (no name)")
                continue

            if not version or version == "RELEASE":
                latest = row.get("latest_version", "").strip()
                if latest and version == "RELEASE":
                    warnings.append(f"Row {row_num}: {name} has version 'RELEASE', using latest_version '{latest}'")
                    version = latest
                elif not version:
                    warnings.append(f"Row {row_num}: {name} skipped (no version)")
                    continue
                else:
                    warnings.append(f"Row {row_num}: {name} has version 'RELEASE', no latest_version fallback")

            if purl_raw and p_ver and p_ver == version:
                purl_with_version = purl_raw
            else:
                t = pkg_type or p_type or "generic"
                ns = namespace or p_ns
                n = name or p_name
                purl_with_version = build_purl(t, ns, n, version) if n and version else ""

            syfter_type = PURL_TYPE_MAP.get(pkg_type, pkg_type or "generic")

            entry = {
                "name": name,
                "version": version,
                "release": "",
                "arch": p_quals.get("arch", "") if purl_raw else "",
                "type": syfter_type,
                "purl": purl_with_version or "",
                "cpes": [],
                "license": license_val,
                "source_rpm": "",
                "epoch": None,
                "source_image": "",
                "layer_id": None,
                "layer_index": None,
            }
            packages.append(entry)

            extras = {}
            for field in EXTRA_FIELDS:
                val = row.get(field, "").strip()
                if not val:
                    for h in row:
                        if h.lower().strip() == field:
                            val = row[h].strip()
                            break
                if val:
                    extras[field] = val
            if extras:
                extra_data[len(packages) - 1] = extras

    return packages, extra_data, warnings


def build_syft_sbom(packages, extra_data, source_path, product, version):
    """Build a syft-json compatible SBOM from CSV-derived packages."""
    artifacts = []
    for i, pkg in enumerate(packages):
        licenses = []
        if pkg.get("license"):
            licenses = [{"value": pkg["license"], "type": "declared"}]

        metadata = {
            "name": pkg["name"],
            "version": pkg["version"],
            "epoch": pkg.get("epoch"),
            "architecture": pkg.get("arch", ""),
            "release": pkg.get("release", ""),
            "sourceRpm": pkg.get("source_rpm", ""),
        }

        if i in extra_data:
            metadata["csv_fields"] = extra_data[i]

        artifact = {
            "id": str(uuid.uuid4()),
            "name": pkg["name"],
            "version": pkg["version"],
            "type": pkg["type"],
            "foundBy": "csv-importer",
            "locations": [{"path": source_path}],
            "licenses": licenses,
            "language": "",
            "cpes": pkg.get("cpes", []),
            "purl": pkg["purl"],
            "metadata": metadata,
        }
        artifacts.append(artifact)

    return {
        "artifacts": artifacts,
        "artifactRelationships": [],
        "files": [],
        "source": {
            "id": str(uuid.uuid4()),
            "name": product,
            "version": version,
            "type": "csv-import",
            "metadata": {"path": source_path},
        },
        "distro": {"name": "", "version": "", "idLike": []},
        "descriptor": {
            "name": "syft",
            "version": "csv-scanner-1.0",
        },
        "schema": {
            "version": "16.0.18",
            "url": "https://raw.githubusercontent.com/anchore/syft/main/schema/json/schema-16.0.18.json",
        },
    }


def print_summary(packages, extra_data, warnings):
    """Print a summary of parsed CSV data."""
    type_counts = Counter(p["type"] for p in packages)
    print(f"\n{'=' * 60}")
    print(f"  Packages parsed: {len(packages)}")
    print(f"  Warnings: {len(warnings)}")
    print(f"{'=' * 60}")
    print(f"\n  By type:")
    for t, c in type_counts.most_common():
        print(f"    {t:12s} {c:>6,}")

    has_purl = sum(1 for p in packages if p["purl"])
    has_license = sum(1 for p in packages if p["license"])
    print(f"\n  PURLs present:    {has_purl:>6,} / {len(packages):,}")
    print(f"  Licenses present: {has_license:>6,} / {len(packages):,}")

    if extra_data:
        status_counts = Counter()
        for extras in extra_data.values():
            s = extras.get("package_status", "")
            if s:
                status_counts[s] += 1
        if status_counts:
            print(f"\n  Package health:")
            for s, c in status_counts.most_common():
                print(f"    {s:12s} {c:>6,}")

    print(f"\n  Sample packages:")
    for i, pkg in enumerate(packages[:10]):
        ver_display = pkg["version"]
        if len(ver_display) > 20:
            ver_display = ver_display[:17] + "..."
        print(f"    [{i:>4}] {pkg['type']:10s} {pkg['name']}@{ver_display}")
        if pkg["purl"]:
            print(f"           purl: {pkg['purl'][:80]}")
    if len(packages) > 10:
        print(f"    ... and {len(packages) - 10:,} more")

    if warnings:
        print(f"\n  Warnings (first 20):")
        for w in warnings[:20]:
            print(f"    {w}")
        if len(warnings) > 20:
            print(f"    ... and {len(warnings) - 20} more")

    print()


def main():
    ap = argparse.ArgumentParser(
        description="Import CSV package lists into syfter",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    ap.add_argument("csv_file", help="Path to the CSV file")
    ap.add_argument("--product", required=True, help="Product name for the scan")
    ap.add_argument("--version", required=True, help="Product version for the scan")
    ap.add_argument("--upload", action="store_true",
                    help="Upload to syfter server (default: dry-run)")
    ap.add_argument("--tags", metavar="TAGS",
                    help="Comma-separated tags to apply to uploaded scans")
    ap.add_argument("--description", metavar="DESC",
                    help="Scan description (default: CSV filename)")

    col_group = ap.add_argument_group("column mapping",
                                      "Override auto-detected column names")
    col_group.add_argument("--col-name", metavar="COL",
                           help="Column for package name")
    col_group.add_argument("--col-version", metavar="COL",
                           help="Column for package version")
    col_group.add_argument("--col-purl", metavar="COL",
                           help="Column for package URL")
    col_group.add_argument("--col-type", metavar="COL",
                           help="Column for package type")
    col_group.add_argument("--col-namespace", metavar="COL",
                           help="Column for package namespace")
    col_group.add_argument("--col-license", metavar="COL",
                           help="Column for license")

    ap.add_argument("--output-json", metavar="PATH",
                    help="Write packages index JSON to file (for inspection)")

    args = ap.parse_args()

    if not os.path.isfile(args.csv_file):
        log.error("CSV file not found: %s", args.csv_file)
        sys.exit(1)

    col_overrides = {}
    if args.col_name:
        col_overrides["name"] = args.col_name
    if args.col_version:
        col_overrides["version"] = args.col_version
    if args.col_purl:
        col_overrides["purl"] = args.col_purl
    if args.col_type:
        col_overrides["type"] = args.col_type
    if args.col_namespace:
        col_overrides["namespace"] = args.col_namespace
    if args.col_license:
        col_overrides["license"] = args.col_license

    log.info("Reading CSV: %s", args.csv_file)
    packages, extra_data, warnings = read_csv(args.csv_file, col_overrides)

    if not packages:
        log.error("No packages found in CSV")
        sys.exit(1)

    print_summary(packages, extra_data, warnings)

    if args.output_json:
        with open(args.output_json, "w") as f:
            json.dump(packages, f, indent=2)
        log.info("Wrote packages index to %s", args.output_json)

    if not args.upload:
        log.info("Dry-run complete. Use --upload to send to syfter server.")
        return

    server_url = os.environ.get("SYFTER_SERVER")
    if not server_url:
        log.error("SYFTER_SERVER environment variable not set")
        sys.exit(1)
    if not os.environ.get("SYFTER_API_KEY"):
        log.error("SYFTER_API_KEY environment variable not set")
        sys.exit(1)

    source_path = args.description or os.path.basename(args.csv_file)
    sbom = build_syft_sbom(packages, extra_data, source_path, args.product, args.version)

    log.info("Uploading %d packages as %s/%s to %s",
             len(packages), args.product, args.version, server_url)

    result = upload_to_syfter(
        server_url, args.product, args.version, source_path,
        sbom, packages,
        source_type="csv-import",
        syft_version="csv-scanner-1.0",
        tags=args.tags,
    )

    log.info("Upload complete: %s", json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
