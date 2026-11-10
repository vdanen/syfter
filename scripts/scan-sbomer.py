#!/usr/bin/env python3
"""
scan-sbomer.py -- SBOMer CycloneDX 1.6 manifest scanner for syfter.

Converts SBOMer middleware manifests (CycloneDX 1.6) into syfter's
package index format and uploads them. Covers middleware products
(EAP, AMQ, Fuse, Quarkus) that aren't in RPM repos or container images.

Usage:
    # Single manifest (file, URL, or SBOMer ID)
    python3 scan-sbomer.py --file manifest.json --product eap --version 7.4.23
    python3 scan-sbomer.py --url https://sbomer.example.com/api/v1beta1/manifests/<id>/bom \\
        --product eap --version 7.4.23
    python3 scan-sbomer.py --dir /path/to/manifests/ --product eap --version 7.4.23

    # Batch discovery from SBOMer API
    python3 scan-sbomer.py --discover --discover-only                   # List all middleware manifests
    python3 scan-sbomer.py --discover --purl-filter eap --discover-only # Filter by purl substring
    python3 scan-sbomer.py --discover --purl-type maven --discover-only # Filter by purl type
    python3 scan-sbomer.py --discover --purl-filter eap                 # Discover and ingest
    python3 scan-sbomer.py --discover --max-manifests 50                # Limit discovery
    python3 scan-sbomer.py --discover --full                            # Force rescan all
    python3 scan-sbomer.py --discover --retry-failed                    # Retry failures

Requires: SYFTER_SERVER and SYFTER_API_KEY environment variables.
Dependencies: Python stdlib only + scanner_common.py.
"""

import argparse
import json
import logging
import os
import sys
import time
from collections import Counter
from urllib.parse import unquote, quote
from urllib.request import Request, urlopen

from scanner_common import upload_to_syfter, load_progress, save_progress

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
log = logging.getLogger("scan-sbomer")

# SBOMer CycloneDX manifest service -- set SBOMER_API_URL to your instance
SBOMER_API = os.environ.get("SBOMER_API_URL", "https://sbomer.example.com/api/v1beta1")
PROGRESS_FILE = "scan-progress-sbomer.json"

# ─── SBOMer API Discovery ────────────────────────────────────────────────────

def sbomer_request(path, timeout=30):
    """GET request to SBOMer API. Returns parsed JSON."""
    url = f"{SBOMER_API}{path}"
    req = Request(url)
    req.add_header("Accept", "application/json")
    api_key = os.environ.get("SBOMER_API_KEY")
    if api_key:
        req.add_header("X-API-KEY", api_key)
    with urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode())


def sbomer_get_bom(manifest_id, timeout=60):
    """Download the CycloneDX BOM content for a manifest."""
    url = f"{SBOMER_API}/manifests/{manifest_id}/bom"
    req = Request(url)
    req.add_header("Accept", "application/json")
    api_key = os.environ.get("SBOMER_API_KEY")
    if api_key:
        req.add_header("X-API-KEY", api_key)
    with urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode())


def derive_product_from_purl(purl):
    """Derive syfter product name and version from a rootPurl.

    pkg:rpm/redhat/eap7-wildfly@7.3.18-3.GA_redhat_00001.1.el7eap?arch=src
      -> product=eap7-wildfly, version=7.3.18
    pkg:maven/org.jboss.eap/wildfly-ee-galleon-pack@7.4.23.GA?type=zip
      -> product=wildfly-ee-galleon-pack, version=7.4.23.GA
    pkg:generic/eap-xp@5.0.1.GA?download_url=...
      -> product=eap-xp, version=5.0.1.GA
    pkg:oci/kafka-42-rhel9@sha256:...?arch=amd64&tag=1.2
      -> product=kafka-42-rhel9, version=1.2
    """
    purl_type, _, name, version, quals = _parse_purl(purl)
    if not name:
        return None, None
    if purl_type == "oci" and quals:
        for q in quals.split("&"):
            if q.startswith("tag="):
                version = q[4:]
                break
        else:
            if version and version.startswith("sha256"):
                return None, None
    if version and "-" in version:
        version = version.split("-")[0]
    return name, version


def discover_manifests(purl_filter=None, purl_type=None, max_manifests=None,
                       page_size=200):
    """Discover manifests from SBOMer API. Yields manifest records."""
    parts = []
    if purl_filter:
        parts.append(f"rootPurl=like='%{purl_filter}%'")
    if purl_type:
        parts.append(f"rootPurl=like='pkg:{purl_type}/%'")

    query = ";".join(parts) if parts else None
    page = 0
    total_yielded = 0

    while True:
        path = f"/manifests?pageSize={page_size}&pageIndex={page}&sort=creationTime%3Ddesc%3D"
        if query:
            path += f"&query={quote(query)}"

        try:
            data = sbomer_request(path)
        except Exception as e:
            log.warning("SBOMer API page %d failed: %s", page, e)
            break

        content = data.get("content", [])
        if not content:
            break

        total_hits = data.get("totalHits", 0)
        if page == 0:
            log.info("SBOMer discovery: %d total manifests matching filters", total_hits)
        elif page % 100 == 0:
            log.info("SBOMer discovery: page %d/%d (%d manifests so far)",
                      page, (total_hits // page_size) + 1, total_yielded)

        for record in content:
            yield record
            total_yielded += 1
            if max_manifests and total_yielded >= max_manifests:
                return

        if len(content) < page_size:
            break
        page += 1


def deduplicate_manifests(manifests):
    """Keep one manifest per unique product:version (deduplicate across arch variants)."""
    seen = {}
    for m in manifests:
        purl = m.get("rootPurl", "")
        p, v = derive_product_from_purl(purl)
        if not p or not v:
            continue
        key = f"{p}:{v}"
        if key not in seen:
            seen[key] = m
    return list(seen.values())


# ─── Package Index ───────────────────────────────────────────────────────────

SBOMER_TYPE_MAP = {
    "rpm": "rpm",
    "java-archive": "java",
}

PURL_TYPE_MAP = {
    "rpm": "rpm",
    "maven": "java",
    "npm": "npm",
    "generic": "generic",
    "pypi": "python",
    "golang": "go-module",
    "gem": "gem",
}


def _parse_purl(purl):
    """Parse a Package URL into (type, namespace, name, version, qualifiers)."""
    if not purl or ":" not in purl:
        return None, None, None, None, {}
    scheme_rest = purl.split(":", 1)
    if len(scheme_rest) != 2:
        return None, None, None, None, {}
    rest = scheme_rest[1]
    qualifiers = {}
    if "?" in rest:
        rest, qs = rest.split("?", 1)
        for pair in qs.split("&"):
            if "=" in pair:
                k, v = pair.split("=", 1)
                qualifiers[k] = unquote(v)
    version = None
    if "@" in rest:
        rest, version = rest.split("@", 1)
    parts = rest.split("/")
    pkg_type = parts[0] if parts else None
    if len(parts) == 3:
        namespace, name = parts[1], parts[2]
    elif len(parts) == 2:
        namespace, name = None, parts[1]
    else:
        namespace, name = None, parts[0] if parts else None
    return pkg_type, namespace, name, version, qualifiers


def extract_product_cpe(cdx_sbom):
    """Extract product-level CPE from metadata.component.evidence.identity."""
    meta_comp = cdx_sbom.get("metadata", {}).get("component", {})
    for ident in meta_comp.get("evidence", {}).get("identity", []):
        if ident.get("field") == "cpe":
            return ident.get("concludedValue", "")
    return ""


def extract_license(comp):
    """Extract license string from a CycloneDX component."""
    for lic_entry in comp.get("licenses", []):
        if "expression" in lic_entry:
            return lic_entry["expression"]
        lic = lic_entry.get("license", {})
        if lic.get("id"):
            return lic["id"]
        if lic.get("name"):
            return lic["name"]
    return ""


def resolve_type(comp, purl_type_raw):
    """Resolve syfter package type from sbomer properties or purl type."""
    for prop in comp.get("properties", []):
        if prop.get("name") == "sbomer:package:type":
            sbomer_type = prop["value"]
            if sbomer_type in SBOMER_TYPE_MAP:
                return SBOMER_TYPE_MAP[sbomer_type]
    if purl_type_raw and purl_type_raw in PURL_TYPE_MAP:
        return PURL_TYPE_MAP[purl_type_raw]
    return "unknown"


def split_rpm_version(version_str):
    """Split RPM version-release string. '0.0.25-6.el8' -> ('0.0.25', '6.el8')."""
    if "-" in version_str:
        idx = version_str.rfind("-")
        return version_str[:idx], version_str[idx + 1:]
    return version_str, ""


def load_manifest(source):
    """Load a CycloneDX manifest from a file path or URL."""
    if source.startswith("http://") or source.startswith("https://"):
        log.info("Fetching manifest from %s", source)
        req = Request(source)
        req.add_header("Accept", "application/json")
        with urlopen(req, timeout=30) as resp:
            return json.loads(resp.read())
    else:
        with open(source) as f:
            return json.load(f)


def _flatten_components(components):
    """Recursively flatten nested CycloneDX components."""
    for comp in components:
        yield comp
        yield from _flatten_components(comp.get("components", []))


def build_packages_index_cyclonedx(cdx_sbom):
    """Build syfter packages_json index from a CycloneDX 1.6 SBOM."""
    packages = []

    product_cpe = extract_product_cpe(cdx_sbom)
    cpes_json = json.dumps([product_cpe]) if product_cpe else "[]"

    for comp in _flatten_components(cdx_sbom.get("components", [])):
        purl = comp.get("purl", "")
        if not purl:
            continue
        if purl.startswith("pkg:oci/"):
            continue

        pkg_type_raw, namespace, purl_name, purl_version, quals = _parse_purl(purl)
        pkg_type = resolve_type(comp, pkg_type_raw)
        license_val = extract_license(comp)

        vendor = comp.get("publisher", "")
        if not vendor:
            vendor = comp.get("supplier", {}).get("name", "")

        name = comp.get("name", purl_name or "")
        version = purl_version or comp.get("version", "")

        entry = {
            "name": name,
            "version": version,
            "type": pkg_type,
            "purl": purl,
            "cpes": cpes_json,
            "license": license_val,
            "source_image": "",
            "layer_id": None,
        }

        if pkg_type == "rpm":
            ver, rel = split_rpm_version(version)
            entry.update({
                "version": ver,
                "release": rel,
                "arch": quals.get("arch", ""),
                "epoch": int(quals["epoch"]) if quals.get("epoch") else None,
                "source_rpm": quals.get("upstream", ""),
                "vendor": vendor,
            })
        else:
            entry.update({
                "release": "",
                "arch": "",
                "epoch": None,
                "source_rpm": "",
            })

        packages.append(entry)

    return packages


def build_cyclonedx_dependencies(cdx_sbom, packages_index):
    """Extract dependency edges from CycloneDX dependencies array."""
    deps_array = cdx_sbom.get("dependencies", [])
    if not deps_array:
        return None

    bomref_to_comp = {}
    for comp in _flatten_components(cdx_sbom.get("components", [])):
        ref = comp.get("bom-ref", "")
        if ref:
            bomref_to_comp[ref] = comp

    known_purls = {p["purl"] for p in packages_index if p.get("purl")}

    deps = []
    for entry in deps_array:
        ref = entry.get("ref", "")
        source_comp = bomref_to_comp.get(ref)
        if not source_comp:
            continue
        s_purl = source_comp.get("purl", "")
        if not s_purl:
            continue
        _, _, s_name, s_ver, s_quals = _parse_purl(s_purl)
        s_name = source_comp.get("name", s_name or "")
        s_ver = s_ver or source_comp.get("version", "")
        s_arch = s_quals.get("arch", "")

        for target_ref in entry.get("dependsOn", []):
            target_comp = bomref_to_comp.get(target_ref)
            if target_comp:
                t_purl = target_comp.get("purl", "")
            else:
                t_purl = target_ref if target_ref.startswith("pkg:") else ""
            if not t_purl:
                continue

            _, _, t_name, t_ver, _ = _parse_purl(t_purl)
            if target_comp:
                t_name = target_comp.get("name", t_name or "")
                t_ver = t_ver or target_comp.get("version", "")

            deps.append({
                "package_name": s_name,
                "package_version": s_ver,
                "package_arch": s_arch,
                "dependency_name": t_purl,
                "dependency_version": t_ver,
                "dependency_flags": None,
                "dependency_type": "depends_on",
            })

            if t_purl not in known_purls:
                known_purls.add(t_purl)
                pkg_type_raw, _, _, _, _ = _parse_purl(t_purl)
                pkg_type = PURL_TYPE_MAP.get(pkg_type_raw, pkg_type_raw or "unknown")
                packages_index.append({
                    "name": t_name or "", "version": t_ver or "",
                    "type": pkg_type, "purl": t_purl, "cpes": "[]",
                    "license": "", "source_image": "", "layer_id": None,
                    "release": "", "arch": "", "epoch": None, "source_rpm": "",
                })

    return deps if deps else None


def scan_sbomer_manifest(source, product, version, server_url, dry_run=False,
                         preloaded_bom=None):
    """Scan a single SBOMer manifest. Returns (status, count, message)."""
    cdx_sbom = preloaded_bom if preloaded_bom else load_manifest(source)

    bom_format = cdx_sbom.get("bomFormat", "")
    spec_version = cdx_sbom.get("specVersion", "")
    if bom_format != "CycloneDX":
        return "skipped", 0, f"Not a CycloneDX manifest (bomFormat={bom_format})"

    packages_index = build_packages_index_cyclonedx(cdx_sbom)
    if not packages_index:
        return "skipped", 0, "No packages found in manifest"

    type_counts = Counter(p["type"] for p in packages_index)
    type_summary = ", ".join(f"{t}: {c}" for t, c in type_counts.most_common())

    meta_comp = cdx_sbom.get("metadata", {}).get("component", {})
    product_cpe = extract_product_cpe(cdx_sbom)

    if dry_run:
        print(f"\n--- Manifest: {os.path.basename(source) if not source.startswith('http') else source} ---")
        print(f"  Format: CycloneDX {spec_version}")
        print(f"  Main component: {meta_comp.get('name', 'N/A')}")
        print(f"  Product CPE: {product_cpe or 'None'}")
        top_level = len(cdx_sbom.get("components", []))
        total = sum(1 for _ in _flatten_components(cdx_sbom.get("components", [])))
        nested_note = f" ({total} with nested)" if total != top_level else ""
        print(f"  Components: {top_level}{nested_note}")
        print(f"  Packages (after filtering): {len(packages_index)}")
        print(f"  Types: {type_summary}")
        print(f"  Upload target: {product}/{version}")
        print()
        for i, pkg in enumerate(packages_index[:5]):
            print(f"  [{i}] {pkg['type']:8s} {pkg['name']}@{pkg['version']}  purl={pkg['purl'][:80]}")
        if len(packages_index) > 5:
            print(f"  ... and {len(packages_index) - 5} more")
        return "dry-run", len(packages_index), f"{len(packages_index)} packages ({type_summary})"

    dependencies_index = build_cyclonedx_dependencies(cdx_sbom, packages_index)
    if dependencies_index:
        log.info("Extracted %d dependency edges from CycloneDX dependencies graph", len(dependencies_index))

    log.info("Uploading %d packages (%s) as %s/%s", len(packages_index), type_summary, product, version)

    tool_version = "sbomer-scanner-1.0"
    tools = cdx_sbom.get("metadata", {}).get("tools", {})
    if isinstance(tools, dict):
        for tool in tools.get("services", []):
            if tool.get("name") == "SBOMer":
                tool_version = f"sbomer-{tool.get('version', 'unknown')}"
                break
        for tool in tools.get("components", []):
            if tool.get("name") == "syft":
                tool_version += f"+syft-{tool.get('version', 'unknown')}"
                break

    upload_to_syfter(
        server_url, product, version, source,
        cdx_sbom, packages_index,
        dependencies_index=dependencies_index,
        source_type="sbomer",
        syft_version=tool_version,
    )

    return "completed", len(packages_index), f"{len(packages_index)} packages ({type_summary})"


def run_discovery(args, server_url):
    """Run SBOMer API discovery and batch ingestion."""
    progress = load_progress(PROGRESS_FILE)

    if args.retry_failed and progress["failed"]:
        log.info("Retrying %d previously failed manifests", len(progress["failed"]))
        progress["failed"] = []
        save_progress(progress, PROGRESS_FILE)

    log.info("Discovering manifests from SBOMer API...")
    all_manifests = list(discover_manifests(
        purl_filter=args.purl_filter,
        purl_type=args.purl_type,
        max_manifests=args.max_manifests,
    ))
    manifests = deduplicate_manifests(all_manifests)
    log.info("Found %d unique manifests (from %d total)", len(manifests), len(all_manifests))

    scan_queue = []
    for m in manifests:
        mid = m["id"]
        purl = m.get("rootPurl", "")
        product, version = derive_product_from_purl(purl)
        if not product or not version:
            continue

        key = f"{product}:{version}"

        if args.discover_only:
            status = "NEW"
            if key in progress["completed"]:
                status = "DONE"
            elif key in progress["failed"]:
                status = "FAIL"
            log.info("[%s] %s %s  --  %s  (sbomer:%s)", status, product, version, purl[:80], mid)
            continue

        if not args.full and key in progress["completed"]:
            continue

        scan_queue.append((mid, purl, product, version, key))

    if args.discover_only:
        done = len(progress["completed"])
        fail = len(progress["failed"])
        log.info("\nSummary: %d manifests, %d completed, %d failed", len(manifests), done, fail)
        return

    if not scan_queue:
        log.info("All manifests up to date. Use --full to force rescan.")
        return

    log.info("Ingesting %d manifests", len(scan_queue))
    scan_start = time.time()
    new_completed = 0
    new_failed = 0
    new_skipped = 0

    for i, (mid, purl, product, version, key) in enumerate(scan_queue, 1):
        try:
            bom = sbomer_get_bom(mid)
            source_url = f"{SBOMER_API}/manifests/{mid}/bom"
            status, count, message = scan_sbomer_manifest(
                source_url, product, version, server_url,
                dry_run=False, preloaded_bom=bom,
            )

            for lst in ("completed", "failed", "skipped"):
                while key in progress[lst]:
                    progress[lst].remove(key)

            if status == "completed":
                progress["completed"].append(key)
                progress["timestamps"][key] = {
                    "sbomer_id": mid,
                    "purl": purl,
                    "scanned_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
                    "package_count": count,
                }
                new_completed += 1
                log.info("[%d/%d] %s %s: %s", i, len(scan_queue), product, version, message)
            elif status == "skipped":
                progress["skipped"].append(key)
                new_skipped += 1
                log.info("[%d/%d] %s %s: SKIP -- %s", i, len(scan_queue), product, version, message)

        except Exception as e:
            for lst in ("completed", "failed", "skipped"):
                while key in progress[lst]:
                    progress[lst].remove(key)
            progress["failed"].append(key)
            new_failed += 1
            log.error("[%d/%d] %s %s: FAIL -- %s", i, len(scan_queue), product, version, e)

        save_progress(progress, PROGRESS_FILE)

    elapsed = time.time() - scan_start
    log.info(
        "\nDone in %.1fm: %d completed, %d skipped, %d failed",
        elapsed / 60, new_completed, new_skipped, new_failed,
    )
    log.info("Overall: %d completed, %d failed",
             len(progress["completed"]), len(progress["failed"]))


def main():
    ap = argparse.ArgumentParser(
        description="SBOMer CycloneDX manifest scanner for syfter",
    )
    source_group = ap.add_mutually_exclusive_group(required=True)
    source_group.add_argument("--file", help="Path to a single CycloneDX manifest")
    source_group.add_argument("--url", help="URL to fetch a CycloneDX manifest")
    source_group.add_argument("--dir", help="Directory of CycloneDX manifests to batch-scan")
    source_group.add_argument("--discover", action="store_true",
                              help="Discover and ingest manifests from SBOMer API")

    ap.add_argument("--product", help="Product name for syfter (required for file/url/dir)")
    ap.add_argument("--version", help="Product version for syfter (required for file/url/dir)")
    ap.add_argument("--dry-run", action="store_true", help="Parse and show summary without uploading")
    ap.add_argument("--source-type", default="sbomer", help="Source type label (default: sbomer)")

    # Discovery options
    ap.add_argument("--discover-only", action="store_true",
                    help="List manifests without ingesting")
    ap.add_argument("--purl-filter", help="Filter manifests by purl substring (e.g., eap, amq)")
    ap.add_argument("--purl-type", help="Filter by purl type (e.g., maven, rpm, generic, oci)")
    ap.add_argument("--max-manifests", type=int,
                    help="Maximum number of manifests to discover")
    ap.add_argument("--full", action="store_true",
                    help="Force rescan of all manifests (ignore progress)")
    ap.add_argument("--retry-failed", action="store_true",
                    help="Retry previously failed manifests")

    args = ap.parse_args()

    server_url = os.environ.get("SYFTER_SERVER", "")
    if not args.dry_run and not args.discover_only and not server_url:
        log.error("SYFTER_SERVER environment variable not set")
        sys.exit(1)

    if args.discover:
        run_discovery(args, server_url)
        return

    if not args.product or not args.version:
        ap.error("--product and --version are required for file/url/dir mode")

    if args.file:
        sources = [args.file]
    elif args.url:
        sources = [args.url]
    elif args.dir:
        sources = sorted(
            os.path.join(args.dir, f)
            for f in os.listdir(args.dir)
            if f.endswith(".json")
        )
        if not sources:
            log.error("No .json files found in %s", args.dir)
            sys.exit(1)
        log.info("Found %d manifests in %s", len(sources), args.dir)

    total = 0
    completed = 0
    failed = 0
    skipped = 0

    for source in sources:
        try:
            status, count, message = scan_sbomer_manifest(
                source, args.product, args.version, server_url,
                dry_run=args.dry_run,
            )
            total += count
            if status == "completed":
                completed += 1
                log.info("OK: %s -- %s", os.path.basename(source), message)
            elif status == "dry-run":
                completed += 1
            elif status == "skipped":
                skipped += 1
                log.warning("SKIP: %s -- %s", os.path.basename(source), message)
        except Exception as e:
            failed += 1
            log.error("FAIL: %s -- %s", os.path.basename(source), e)

    print(f"\nSummary: {completed} completed, {failed} failed, {skipped} skipped, {total} total packages")


if __name__ == "__main__":
    main()
