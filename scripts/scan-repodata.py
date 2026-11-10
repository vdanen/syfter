#!/usr/bin/env python3
"""
scan-repodata.py — Fast RPM repo scanner using repodata metadata.

Instead of mirroring entire repos with wget (5-20GB each), this downloads
only the repodata/primary.xml.gz (~1-10MB) from each repo and builds
syft-compatible SBOMs from the package metadata.

Speed comparison:
  - scan-all.py (wget): ~3.5 hours per repo (14GB download)
  - scan-repodata.py:   ~10-30 seconds per repo (1-10MB download)

Usage:
    python3 scan-repodata.py                          # Delta scan
    python3 scan-repodata.py --full                   # Full rescan
    python3 scan-repodata.py --discover-only          # List repos
    python3 scan-repodata.py --trees dist/rhel10      # Specific trees
    python3 scan-repodata.py --retry-failed           # Retry failures
    python3 scan-repodata.py --workers 8              # Parallel scanning
    python3 scan-repodata.py --reset                  # Start fresh

Prerequisites:
    - SYFTER_SERVER set to the syfter API endpoint
    - Network access to your Pulp content mirror (set PULP_BASE_URL)
"""

import argparse
import gzip
import json
import logging
import os
import re
import sys
import time
import uuid
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from html.parser import HTMLParser
from urllib.error import HTTPError, URLError
from urllib.request import urlopen, Request

import ssl

from scanner_common import upload_to_syfter, load_progress, save_progress

# ─── Configuration ────────────────────────────────────────────────────────────

# Pulp RPM content mirror -- set PULP_BASE_URL to your mirror's base URL
PULP_BASE = os.environ.get("PULP_BASE_URL", "https://pulp.example.com")
CONTENT_URL = f"{PULP_BASE}/content"
MAX_CRAWL_DEPTH = 15
CRAWL_DELAY = 0.15
SCAN_RETRIES = 3

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROGRESS_FILE = os.path.join(SCRIPT_DIR, "scan-progress-repodata.json")
LOG_FILE = os.path.join(SCRIPT_DIR, "scan-repodata.log")

# Content trees to crawl
DEFAULT_TREES = [
    "dist/rhel8", "dist/rhel9", "dist/rhel10",
    "dist/rhel", "dist/rhel-alt",
    "dist/layered",
    "dist/rhivos1", "dist/rhivos2",
    "dist/middleware", "dist/rhs", "dist/cf-me", "dist/rhes", "dist/suse",
    "aus", "e4s", "e6s", "els", "eus", "extended-eus", "tus",
    "beta", "public",
]

SKIP_DIRS = {
    "debug", "source", "repodata", "rhui", "hidden",
    "Packages", "listing", "images", "iso", "kickstart",
    "isos", "tree-images",
}

KNOWN_ARCHES = {
    "x86_64", "aarch64", "ppc64le", "s390x", "i386", "i686", "ia64",
    "noarch", "src",
    "arm-64", "arm", "power", "power-le", "power-9", "system-z", "itanium",
}

# XML namespaces for primary.xml
NS = {
    "common": "http://linux.duke.edu/metadata/common",
    "rpm": "http://linux.duke.edu/metadata/rpm",
    "fl": "http://linux.duke.edu/metadata/filelists",
}


# ─── HTML Directory Listing Parser ────────────────────────────────────────────

class DirParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.dirs = []

    def handle_starttag(self, tag, attrs):
        if tag == "a":
            href = dict(attrs).get("href", "")
            if href.endswith("/") and not href.startswith(("/", "?", "..")):
                self.dirs.append(href.rstrip("/"))


def list_dirs(url, retries=2):
    target = url if url.endswith("/") else url + "/"
    for attempt in range(retries + 1):
        try:
            with urlopen(target, timeout=30) as resp:
                html = resp.read().decode("utf-8", errors="replace")
            parser = DirParser()
            parser.feed(html)
            time.sleep(CRAWL_DELAY)
            return parser.dirs
        except HTTPError as e:
            if e.code in (404, 403):
                return []
            if attempt < retries:
                time.sleep(2 ** attempt)
                continue
            return []
        except (URLError, OSError):
            if attempt < retries:
                time.sleep(2 ** attempt)
                continue
            return []


# ─── Delta Scanning ───────────────────────────────────────────────────────────

def get_last_modified(url):
    try:
        req = Request(url if url.endswith("/") else url + "/", method="HEAD")
        with urlopen(req, timeout=15) as resp:
            return resp.headers.get("Last-Modified")
    except Exception:
        try:
            with urlopen(url if url.endswith("/") else url + "/", timeout=15) as resp:
                resp.read(1)
                return resp.headers.get("Last-Modified")
        except Exception:
            return None


def repo_has_changed(packages_url, key, progress):
    timestamps = progress.get("timestamps", {})
    prev = timestamps.get(key)
    if not prev:
        return True
    prev_modified = prev.get("last_modified")
    if not prev_modified:
        return True
    current_modified = get_last_modified(packages_url)
    if not current_modified:
        return True
    return current_modified != prev_modified


def record_timestamp(progress, key, packages_url):
    if "timestamps" not in progress:
        progress["timestamps"] = {}
    last_mod = get_last_modified(packages_url)
    progress["timestamps"][key] = {
        "last_modified": last_mod,
        "scanned_at": datetime.now().isoformat(),
    }


# ─── Product-Definitions Filter ──────────────────────────────────────────────

_VARIANT_RE = re.compile(r"^([A-Za-z]+)-(\d+\.\d+)")
_COMPOSE_VARIANT_RE = re.compile(r"^([A-Za-z]+)$")
_RHEL_MODULE_RE = re.compile(r"rhel-(\d+)")
_RHEL_PRODUCT_RE = re.compile(r"^(?:aus|e4s|eus|tus|beta|beta-layered)?-?rhel-?(\d+)")


def load_prod_defs(repo_path):
    """Parse a product-definitions checkout and return the set of active
    (rhel_major, minor_version, variant_lower) tuples.

    For example, if rhel-9 module has active stream rhel-9.6.z with
    errata_info variant "BaseOS-9.6.0.Z.EUS", this yields ("9", "9.6", "baseos").
    """
    data_dir = os.path.join(repo_path, "data")
    if not os.path.isdir(data_dir):
        sys.exit(f"Error: {data_dir} not found -- is this a product-definitions checkout?")

    allowed = set()
    module_count = 0

    for dirpath, _dirnames, filenames in os.walk(data_dir):
        for fname in filenames:
            if not fname.endswith(".json"):
                continue
            fpath = os.path.join(dirpath, fname)
            try:
                with open(fpath) as f:
                    data = json.load(f)
            except (json.JSONDecodeError, OSError):
                continue

            ps_modules = data.get("ps_modules", {})
            ps_streams = data.get("ps_update_streams", {})

            for mod_name, mod_data in ps_modules.items():
                m = _RHEL_MODULE_RE.search(mod_name)
                if not m:
                    continue
                rhel_major = m.group(1)

                if mod_name.startswith("rhel-br-"):
                    continue

                active_streams = mod_data.get("active_ps_update_streams", [])
                if not active_streams:
                    continue
                module_count += 1

                for stream_name in active_streams:
                    stream = ps_streams.get(stream_name, {})

                    for ei in stream.get("errata_info", []):
                        for pv in ei.get("product_versions", []):
                            for variant in pv.get("variants", []):
                                vm = _VARIANT_RE.match(variant)
                                if vm:
                                    variant_lower = vm.group(1).lower()
                                    minor_ver = vm.group(2)
                                    allowed.add((rhel_major, minor_ver, variant_lower))

                    for compose in stream.get("composes", []):
                        stream_ver_m = re.search(r"(\d+\.\d+)", stream_name)
                        if not stream_ver_m:
                            continue
                        minor_ver = stream_ver_m.group(1)
                        for variant in compose.get("variants", []):
                            allowed.add((rhel_major, minor_ver, variant.lower()))

    return allowed, module_count


def matches_prod_defs(product, version, allowed):
    """Check if a discovered repo matches any active product-definitions stream.

    Non-RHEL products (no rhelN in name) pass through unconditionally.
    """
    m = _RHEL_PRODUCT_RE.search(product)
    if not m:
        return True
    rhel_major = m.group(1)

    parts = product.split("-")
    rhel_idx = next(
        (i for i, p in enumerate(parts) if re.match(rf"^rhel{rhel_major}$", p)), None
    )
    if rhel_idx is None or rhel_idx + 1 >= len(parts):
        return True
    variant = "-".join(parts[rhel_idx + 1:]).lower()

    ver_m = re.match(r"(\d+\.\d+)", version)
    if not ver_m:
        return True
    minor_ver = ver_m.group(1)

    return (rhel_major, minor_ver, variant) in allowed


# ─── Repo Discovery ──────────────────────────────────────────────────────────

def discover_repos(base_url, rel_path="", depth=0):
    if depth > MAX_CRAWL_DEPTH:
        return
    url = f"{base_url}/{rel_path}".rstrip("/") if rel_path else base_url
    dirs = list_dirs(url)
    if not dirs:
        return
    if "Packages" in dirs:
        yield (f"{url}/Packages", url, rel_path)
        return
    if "os" in dirs:
        sub = f"{rel_path}/os".lstrip("/")
        yield from discover_repos(base_url, sub, depth + 1)
        return
    for d in sorted(dirs):
        if d in SKIP_DIRS:
            continue
        sub = f"{rel_path}/{d}".lstrip("/")
        yield from discover_repos(base_url, sub, depth + 1)


def _dedup_versions(versions):
    """Remove redundant major versions when a more specific minor exists.

    e.g. ["7", "7.6"] -> ["7.6"], ["5", "5Server"] -> ["5Server"]
    but ["8.2", "6.10"] stays as-is (different major = different products).
    """
    if len(versions) < 2:
        return versions
    keep = []
    skip = set()
    for i, v in enumerate(versions):
        for j, other in enumerate(versions):
            if i != j and other.startswith(v + ".") or other.startswith(v.rstrip(".") + "S"):
                skip.add(i)
                break
    for i, v in enumerate(versions):
        if i not in skip:
            keep.append(v)
    return keep or versions


def path_to_scan_info(tree, repo_path):
    raw = f"{tree}/{repo_path}".strip("/")
    parts = [p for p in raw.split("/") if p not in ("os", "Packages", "dist")]
    arch = "noarch"
    remaining = []
    for p in parts:
        if p in KNOWN_ARCHES:
            arch = p
        else:
            remaining.append(p)
    versions = []
    names = []
    for p in remaining:
        if re.match(r"^\d", p):
            versions.append(p)
        else:
            names.append(p)
    deduped = []
    for n in names:
        if not deduped or n != deduped[-1]:
            deduped.append(n)
    names = deduped
    versions = _dedup_versions(versions)
    product = "-".join(names) if names else tree.replace("/", "-")
    version = ("-".join(versions) + "-" + arch) if versions else arch
    description = " ".join([p for p in raw.split("/") if p not in ("os", "Packages")])
    return product, version, description


# ─── CPE Generation ──────────────────────────────────────────────────────────

def normalize_vendor(vendor):
    if not vendor:
        return "redhat"
    v = vendor.lower()
    if "red hat" in v:
        return "redhat"
    for suffix in [", inc.", ", inc", " inc.", " inc", ", ltd.", " ltd"]:
        v = v.replace(suffix, "")
    return re.sub(r'[^a-z0-9]+', '_', v).strip('_') or "redhat"


def generate_cpes(name, raw_version, release, vendor):
    v = normalize_vendor(vendor)
    n = re.sub(r'[^a-z0-9._-]', lambda m: '\\' + m.group(), name.lower())
    cpes = [
        f"cpe:2.3:a:{v}:{n}:{raw_version}:{release}:*:*:*:*:*:*",
    ]
    return cpes


# ─── Repodata Parsing ─────────────────────────────────────────────────────────

def find_repodata_urls(repo_url):
    """Find primary.xml.gz and filelists.xml.gz URLs from repodata/."""
    repodata_url = repo_url.rstrip("/") + "/repodata/"
    try:
        with urlopen(repodata_url, timeout=15) as resp:
            html = resp.read().decode("utf-8", errors="replace")
    except Exception:
        return None, None

    primaries = re.findall(r'href="([^"]*primary\.xml\.gz)"', html)
    filelists = re.findall(r'href="([^"]*filelists\.xml\.gz)"', html)

    primary_url = (repodata_url + sorted(primaries)[-1]) if primaries else None
    filelists_url = (repodata_url + sorted(filelists)[-1]) if filelists else None
    return primary_url, filelists_url


def download_repodata_xml(url):
    """Download and decompress a repodata .xml.gz, return parsed XML root."""
    with urlopen(url, timeout=120) as resp:
        compressed = resp.read()
    xml_data = gzip.decompress(compressed)
    return ET.fromstring(xml_data), len(compressed)


def parse_filelists(root):
    """Parse filelists.xml, return dict of pkgid -> list of file paths."""
    files_by_pkgid = {}
    for pkg_elem in root.findall("fl:package", NS):
        pkgid = pkg_elem.get("pkgid", "")
        if not pkgid:
            continue
        files = []
        for file_elem in pkg_elem.findall("fl:file", NS):
            path = file_elem.text
            if path:
                files.append(path)
        if files:
            files_by_pkgid[pkgid] = files
    return files_by_pkgid


def parse_packages_from_primary(root):
    """Parse all packages from primary.xml into a list of dicts."""
    packages = []
    for pkg_elem in root.findall("common:package", NS):
        if pkg_elem.get("type") != "rpm":
            continue

        name = pkg_elem.findtext("common:name", "", NS)
        arch = pkg_elem.findtext("common:arch", "", NS)

        # Skip debuginfo/debugsource
        if "-debuginfo" in name or "-debugsource" in name:
            continue
        # Skip source RPMs
        if arch == "src":
            continue

        ver_elem = pkg_elem.find("common:version", NS)
        epoch = ver_elem.get("epoch", "0") if ver_elem is not None else "0"
        version = ver_elem.get("ver", "") if ver_elem is not None else ""
        release = ver_elem.get("rel", "") if ver_elem is not None else ""

        summary = pkg_elem.findtext("common:summary", "", NS)
        # Skip description — it bloats the SBOM significantly and the server's
        # validation truncates gzip data >10KB then fails decompression
        url = pkg_elem.findtext("common:url", "", NS)
        packager = pkg_elem.findtext("common:packager", "", NS)

        size_elem = pkg_elem.find("common:size", NS)
        pkg_size = int(size_elem.get("package", "0")) if size_elem is not None else 0
        installed_size = int(size_elem.get("installed", "0")) if size_elem is not None else 0

        checksum_elem = pkg_elem.find("common:checksum", NS)
        checksum_type = checksum_elem.get("type", "sha256") if checksum_elem is not None else "sha256"
        checksum_val = checksum_elem.text if checksum_elem is not None else ""

        location_elem = pkg_elem.find("common:location", NS)
        location = location_elem.get("href", "") if location_elem is not None else ""

        time_elem = pkg_elem.find("common:time", NS)
        build_time = int(time_elem.get("build", "0")) if time_elem is not None else 0

        # Fields from <format> element (rpm: namespace)
        format_elem = pkg_elem.find("common:format", NS)
        license_val = ""
        source_rpm = ""
        vendor = ""
        requires = []
        provides = []
        if format_elem is not None:
            license_val = format_elem.findtext("rpm:license", "", NS)
            source_rpm = format_elem.findtext("rpm:sourcerpm", "", NS)
            vendor = format_elem.findtext("rpm:vendor", "", NS)

            req_elem = format_elem.find("rpm:requires", NS)
            if req_elem is not None:
                for entry in req_elem.findall("rpm:entry", NS):
                    req = {"name": entry.get("name", "")}
                    flags = entry.get("flags")
                    if flags:
                        req["flags"] = flags
                        ver = entry.get("ver", "")
                        rel = entry.get("rel", "")
                        req["version"] = f"{ver}-{rel}" if rel else ver
                    else:
                        req["flags"] = None
                        req["version"] = None
                    requires.append(req)

            prov_elem = format_elem.find("rpm:provides", NS)
            if prov_elem is not None:
                for entry in prov_elem.findall("rpm:entry", NS):
                    prov = {"name": entry.get("name", "")}
                    flags = entry.get("flags")
                    if flags:
                        prov["flags"] = flags
                        ver = entry.get("ver", "")
                        rel = entry.get("rel", "")
                        prov["version"] = f"{ver}-{rel}" if rel else ver
                    else:
                        prov["flags"] = None
                        prov["version"] = None
                    provides.append(prov)

        # Build PURL
        purl = f"pkg:rpm/redhat/{name}@{version}-{release}?arch={arch}"
        if epoch and epoch != "0":
            purl += f"&epoch={epoch}"

        cpes = generate_cpes(name, version, release, vendor or packager)

        packages.append({
            "name": name,
            "version": f"{version}-{release}",
            "raw_version": version,
            "release": release,
            "epoch": epoch,
            "arch": arch,
            "summary": summary,
            "description": "",
            "url": url,
            "packager": packager,
            "license": license_val,
            "source_rpm": source_rpm,
            "vendor": vendor or packager or "Red Hat, Inc.",
            "size": pkg_size,
            "installed_size": installed_size,
            "checksum_type": checksum_type,
            "checksum": checksum_val,
            "location": location,
            "build_time": build_time,
            "purl": purl,
            "cpes": cpes,
            "requires": requires,
            "provides": provides,
        })
    return packages


# ─── SBOM Generation ──────────────────────────────────────────────────────────

def build_syft_sbom(packages, source_path, source_name="", source_version=""):
    """Build a syft-json compatible SBOM from parsed package metadata."""
    artifacts = []
    all_files = []
    for i, pkg in enumerate(packages):
        licenses = []
        if pkg.get("license"):
            licenses = [{"value": pkg["license"], "type": "declared"}]

        artifact = {
            "id": str(uuid.uuid4()),
            "name": pkg["name"],
            "version": pkg["version"],
            "type": "rpm",
            "foundBy": "repodata-cataloger",
            "locations": [{"path": pkg["location"]}],
            "licenses": licenses,
            "language": "",
            "cpes": pkg.get("cpes", []),
            "purl": pkg["purl"],
            "metadata": {
                "name": pkg["name"],
                "version": pkg["version"],
                "epoch": int(pkg["epoch"]) if pkg["epoch"] else None,
                "architecture": pkg["arch"],
                "release": pkg.get("release", ""),
                "sourceRpm": pkg.get("source_rpm", ""),
                "size": pkg["installed_size"],
                "vendor": pkg.get("vendor", "Red Hat, Inc."),
                "modularityLabel": "",
                "summary": pkg["summary"],
            },
        }
        artifacts.append(artifact)

        for fpath in pkg.get("files", []):
            all_files.append({
                "id": str(uuid.uuid4()),
                "location": {"path": fpath},
                "metadata": {"type": "RegularFile"},
                "digests": [],
            })

    sbom = {
        "artifacts": artifacts,
        "artifactRelationships": [],
        "files": all_files,
        "source": {
            "id": str(uuid.uuid4()),
            "name": source_name or source_path,
            "version": source_version,
            "type": "directory",
            "metadata": {
                "path": source_path,
            },
        },
        "distro": {
            "name": "redhat",
            "version": "",
            "idLike": ["rhel", "fedora"],
        },
        "descriptor": {
            "name": "syft",
            "version": "repodata-scanner-1.0",
        },
        "schema": {
            "version": "16.0.18",
            "url": "https://raw.githubusercontent.com/anchore/syft/main/schema/json/schema-16.0.18.json",
        },
    }
    return sbom


def build_packages_index(packages):
    """Build the packages_json index that syfter expects."""
    index = []
    for pkg in packages:
        entry = {
            "name": pkg["name"],
            "version": pkg["version"],
            "release": pkg.get("release", ""),
            "arch": pkg["arch"],
            "type": "rpm",
            "purl": pkg["purl"],
            "cpes": pkg.get("cpes", []),
            "license": pkg.get("license", ""),
            "source_rpm": pkg.get("source_rpm", ""),
            "epoch": int(pkg["epoch"]) if pkg["epoch"] else None,
            "metadata": {
                "architecture": pkg["arch"],
                "epoch": int(pkg["epoch"]) if pkg["epoch"] else None,
                "source_rpm": pkg.get("source_rpm", ""),
                "summary": pkg["summary"],
            },
        }
        index.append(entry)
    return index


def build_dependencies_index(packages):
    """Build the dependencies_json index for upload to syfter."""
    deps = []
    for pkg in packages:
        pkg_name = pkg["name"]
        pkg_version = pkg["version"]
        pkg_arch = pkg["arch"]

        for req in pkg.get("requires", []):
            deps.append({
                "package_name": pkg_name,
                "package_version": pkg_version,
                "package_arch": pkg_arch,
                "dependency_name": req["name"],
                "dependency_version": req.get("version"),
                "dependency_flags": req.get("flags"),
                "dependency_type": "requires",
            })

        for prov in pkg.get("provides", []):
            deps.append({
                "package_name": pkg_name,
                "package_version": pkg_version,
                "package_arch": pkg_arch,
                "dependency_name": prov["name"],
                "dependency_version": prov.get("version"),
                "dependency_flags": prov.get("flags"),
                "dependency_type": "provides",
            })

    return deps


# ─── Scanning ─────────────────────────────────────────────────────────────────

def scan_repo(repo_url, packages_url, product, version, description, server_url,
              include_files=False, max_files=100000, include_deps=True):
    """Scan a single repo via repodata. Returns (status, package_count, message)."""
    primary_url, filelists_url = find_repodata_urls(repo_url)
    if not primary_url:
        return "skipped", 0, "No repodata/primary.xml.gz found"

    try:
        root, dl_size = download_repodata_xml(primary_url)
    except Exception as e:
        return "failed", 0, f"Failed to download primary.xml: {e}"

    packages = parse_packages_from_primary(root)
    if not packages:
        return "skipped", 0, "No non-debug packages in repodata"

    file_count = 0
    if include_files and filelists_url:
        try:
            fl_root, fl_size = download_repodata_xml(filelists_url)
            dl_size += fl_size
            files_by_pkgid = parse_filelists(fl_root)
            del fl_root

            total_files = sum(len(f) for f in files_by_pkgid.values())
            if total_files <= max_files:
                for pkg in packages:
                    pkg_files = files_by_pkgid.get(pkg["checksum"], [])
                    pkg["files"] = pkg_files
                    file_count += len(pkg_files)
            else:
                logging.info(f"  Skipping files ({total_files} > {max_files} threshold)")
        except Exception as e:
            logging.warning(f"  Filelists parse failed (continuing without): {e}")

    full_sbom = build_syft_sbom(packages, packages_url, product, version)
    packages_index = build_packages_index(packages)
    dependencies_index = build_dependencies_index(packages) if include_deps else None

    try:
        result = upload_to_syfter(server_url, product, version, packages_url,
                                  full_sbom, packages_index, dependencies_index)
        parts = [f"{dl_size/1024:.0f}KB repodata", f"{len(packages)} pkgs"]
        if dependencies_index:
            parts.append(f"{len(dependencies_index)} deps")
        if file_count:
            parts.append(f"{file_count} files")
        return "completed", len(packages), f"Uploaded ({', '.join(parts)})"
    except Exception as e:
        return "failed", 0, f"Upload failed: {e}"


# ─── Connectivity ─────────────────────────────────────────────────────────────

def check_pulp_reachable():
    test_url = f"{PULP_BASE}/content/dist/rhel10/"
    while True:
        try:
            with urlopen(test_url, timeout=10) as resp:
                resp.read(100)
            return
        except Exception:
            logging.warning("  Pulp mirror unreachable -- retrying in 30s...")
            time.sleep(30)


# ─── Main ─────────────────────────────────────────────────────────────────────

def main():
    ap = argparse.ArgumentParser(
        description="Fast RPM repo scanner using repodata metadata"
    )
    ap.add_argument("--discover-only", action="store_true")
    ap.add_argument("--trees", nargs="+")
    ap.add_argument("--full", action="store_true")
    ap.add_argument("--retry-failed", action="store_true")
    ap.add_argument("--reset", action="store_true")
    ap.add_argument("--workers", type=int, default=2,
                    help="Number of parallel workers (default: 2)")
    ap.add_argument("--include-files", action="store_true",
                    help="Parse filelists.xml.gz for file-level inventory")
    ap.add_argument("--max-files", type=int, default=100000,
                    help="Skip file data when repo exceeds this count (default: 100000)")
    ap.add_argument("--no-deps", action="store_true",
                    help="Skip dependency extraction (requires/provides)")
    ap.add_argument("--prod-defs", metavar="PATH",
                    help="Path to product-definitions checkout; only scan repos "
                         "matching active ps_update_streams")
    ap.add_argument("--prod-defs-report", action="store_true",
                    help="With --discover-only, show which repos pass the filter")
    args = ap.parse_args()

    server_url = os.environ.get("SYFTER_SERVER")
    if not server_url and not args.discover_only:
        sys.exit("Error: SYFTER_SERVER not set")

    prod_defs_filter = None
    if args.prod_defs:
        prod_defs_filter, mod_count = load_prod_defs(args.prod_defs)
        print(f"Product-definitions filter active: "
              f"{len(prod_defs_filter)} active stream/variant combos "
              f"from {mod_count} modules")

    # Logging
    log_fmt = logging.Formatter("%(asctime)s  %(message)s", datefmt="%Y-%m-%d %H:%M:%S")
    logger = logging.getLogger()
    logger.setLevel(logging.INFO)
    fh = logging.FileHandler(LOG_FILE)
    fh.setFormatter(log_fmt)
    logger.addHandler(fh)
    if sys.stdout.isatty() or os.environ.get("SCAN_ALL_VERBOSE"):
        sh = logging.StreamHandler()
        sh.setFormatter(log_fmt)
        logger.addHandler(sh)

    if args.reset and os.path.exists(PROGRESS_FILE):
        os.remove(PROGRESS_FILE)
    progress = load_progress(PROGRESS_FILE)

    if args.retry_failed and progress["failed"]:
        logging.info(f"Retrying {len(progress['failed'])} previously failed repos")
        progress["failed"] = []
        save_progress(progress, PROGRESS_FILE)

    trees = args.trees or DEFAULT_TREES

    # ── Discovery ──
    check_pulp_reachable()
    all_repos = []
    logging.info(f"Discovering repos across {len(trees)} content trees...")

    filtered_count = 0
    for tree in trees:
        tree_url = f"{CONTENT_URL}/{tree}"
        logging.info(f"  {tree} ...")
        count = 0
        tree_filtered = 0
        for packages_url, repo_url, repo_path in discover_repos(tree_url):
            product, version, desc = path_to_scan_info(tree, repo_path)
            key = f"{product}:{version}"
            if prod_defs_filter is not None and not matches_prod_defs(product, version, prod_defs_filter):
                tree_filtered += 1
                continue
            all_repos.append((packages_url, repo_url, product, version, desc, key))
            count += 1
        parts = []
        if count:
            parts.append(f"{count} repos")
        if tree_filtered:
            parts.append(f"{tree_filtered} filtered out by prod-defs")
            filtered_count += tree_filtered
        if parts:
            logging.info(f"    -> {', '.join(parts)}")

    filter_msg = f" ({filtered_count} filtered by prod-defs)" if filtered_count else ""
    logging.info(f"\nDiscovered {len(all_repos)} repos to scan{filter_msg}\n")

    # ── Discover-only ──
    if args.discover_only:
        completed = set(progress["completed"])
        skipped = set(progress["skipped"])
        failed = set(progress["failed"])
        for _, _, product, version, desc, key in all_repos:
            if key in completed:
                tag = "DONE"
            elif key in skipped:
                tag = "SKIP"
            elif key in failed:
                tag = "FAIL"
            else:
                tag = "TODO"
            print(f"[{tag}] {product}  {version}  --  {desc}")
        todo = sum(1 for *_, k in all_repos
                   if k not in completed and k not in skipped and k not in failed)
        print(f"\n{len(all_repos)} total | {len(completed)} done | "
              f"{len(skipped)} skipped | {len(failed)} failed | {todo} new")
        if filtered_count:
            print(f"{filtered_count} repos excluded by product-definitions filter")
        if args.prod_defs_report and prod_defs_filter is not None:
            print(f"\n--- Product-definitions active streams ---")
            by_major = {}
            for rhel_major, minor_ver, variant in sorted(prod_defs_filter):
                by_major.setdefault(f"rhel-{rhel_major}", set()).add(
                    f"{minor_ver}/{variant}"
                )
            for mod, entries in sorted(by_major.items()):
                print(f"  {mod}: {', '.join(sorted(entries))}")
        return

    # ── Build scan queue ──
    completed = set(progress["completed"])
    skipped = set(progress["skipped"])
    failed = set(progress["failed"])

    scan_queue = []
    delta_skipped = 0

    for url, repo_url, product, version, desc, key in all_repos:
        if key in failed and not args.full:
            continue
        if key not in completed and key not in skipped:
            scan_queue.append((url, repo_url, product, version, desc, key))
            continue
        if key in skipped:
            scan_queue.append((url, repo_url, product, version, desc, key))
            continue
        if key in completed:
            if args.full:
                scan_queue.append((url, repo_url, product, version, desc, key))
                continue
            if repo_has_changed(url, key, progress):
                scan_queue.append((url, repo_url, product, version, desc, key))
                continue
            delta_skipped += 1

    logging.info(f"Completed (previous): {len(completed)}")
    logging.info(f"Skipped (empty):      {len(skipped)}")
    logging.info(f"Failed:               {len(failed)}")
    logging.info(f"Unchanged (delta):    {delta_skipped}")
    logging.info(f"To scan:              {len(scan_queue)}")

    if not scan_queue:
        logging.info("\nNothing to scan — all repos are up to date.")
        return

    # ── Scanning ──
    scan_start = time.time()
    scanned_count = 0
    new_completed = 0
    new_skipped = 0
    new_failed = 0

    def process_repo(item):
        url, repo_url, product, version, desc, key = item
        check_pulp_reachable()
        for attempt in range(1, SCAN_RETRIES + 1):
            try:
                status, pkg_count, msg = scan_repo(
                    repo_url, url, product, version, desc, server_url,
                    include_files=args.include_files,
                    max_files=args.max_files,
                    include_deps=not args.no_deps,
                )
                return key, url, product, version, desc, status, pkg_count, msg
            except Exception as e:
                if attempt < SCAN_RETRIES:
                    time.sleep(5 * attempt)
                    continue
                return key, url, product, version, desc, "failed", 0, str(e)

    workers = min(args.workers, len(scan_queue))
    logging.info(f"Scanning with {workers} parallel workers...\n")

    if workers <= 1:
        # Sequential mode
        for i, item in enumerate(scan_queue, 1):
            url, repo_url, product, version, desc, key = item
            logging.info(f"[{i}/{len(scan_queue)}] {desc}")

            if scanned_count > 0:
                elapsed = time.time() - scan_start
                avg = elapsed / scanned_count
                eta_secs = avg * (len(scan_queue) - i + 1)
                eta_m = int(eta_secs // 60)
                logging.info(f"  ETA: ~{eta_m}m remaining")

            key, _, _, _, _, status, pkg_count, msg = process_repo(item)
            logging.info(f"  {status}: {msg}")

            for lst in ("completed", "skipped", "failed"):
                while key in progress[lst]:
                    progress[lst].remove(key)
            progress[status].append(key)
            if status == "completed":
                record_timestamp(progress, key, url)
                new_completed += 1
            elif status == "skipped":
                new_skipped += 1
            else:
                new_failed += 1
            save_progress(progress, PROGRESS_FILE)
            scanned_count += 1
            # Throttle uploads to avoid overwhelming the API server
            if status == "completed":
                time.sleep(2)
    else:
        # Parallel mode
        with ThreadPoolExecutor(max_workers=workers) as executor:
            futures = {}
            for i, item in enumerate(scan_queue):
                f = executor.submit(process_repo, item)
                futures[f] = (i + 1, item)

            for future in as_completed(futures):
                idx, item = futures[future]
                try:
                    key, url, product, version, desc, status, pkg_count, msg = future.result()
                except Exception as e:
                    key = item[5]
                    url = item[0]
                    status = "failed"
                    msg = str(e)
                    pkg_count = 0

                logging.info(f"[{idx}/{len(scan_queue)}] {item[4]}: {status} — {msg}")

                for lst in ("completed", "skipped", "failed"):
                    while key in progress[lst]:
                        progress[lst].remove(key)
                progress[status].append(key)
                if status == "completed":
                    record_timestamp(progress, key, url)
                    new_completed += 1
                elif status == "skipped":
                    new_skipped += 1
                else:
                    new_failed += 1
                save_progress(progress, PROGRESS_FILE)
                scanned_count += 1

                if scanned_count % 50 == 0:
                    elapsed = time.time() - scan_start
                    rate = scanned_count / elapsed * 60
                    logging.info(f"  Progress: {scanned_count}/{len(scan_queue)} ({rate:.0f}/min)")

    # ── Summary ──
    elapsed = time.time() - scan_start
    hours = int(elapsed // 3600)
    mins = int((elapsed % 3600) // 60)

    logging.info(f"\n{'='*60}")
    logging.info(f"COMPLETE  ({hours}h {mins}m elapsed)")
    logging.info(f"  This run:  {new_completed} scanned, {new_skipped} empty, {new_failed} failed")
    logging.info(f"  Overall:   {len(progress['completed'])} completed, "
                 f"{len(progress['skipped'])} skipped, {len(progress['failed'])} failed")
    if delta_skipped:
        logging.info(f"  Unchanged: {delta_skipped} repos skipped (delta)")
    logging.info(f"{'='*60}")

    if progress["failed"]:
        logging.info("\nFailed repos:")
        for key in progress["failed"]:
            logging.info(f"  {key}")


if __name__ == "__main__":
    main()
