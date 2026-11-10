#!/usr/bin/env python3
"""
scan-containers.py -- Container image scanner for syfter.

Downloads Red Hat's official signed SBOMs (SPDX 2.3) from container
image registries via OCI artifact tags, then uploads them to the syfter
API. Falls back to local syft scanning for images without published SBOMs.

Supports Pyxis API discovery, parallel workers, delta scanning (by image
digest), and CSV inventory for batch scanning.

Usage:
    python3 scan-containers.py                                  # Delta scan from inventory
    python3 scan-containers.py --full                           # Force full rescan
    python3 scan-containers.py --retry-failed                   # Retry failures
    python3 scan-containers.py --discover-only                  # List images, don't scan
    python3 scan-containers.py --workers 2                      # Parallel workers (default: 2)
    python3 scan-containers.py --image <ref>                    # Scan single image
    python3 scan-containers.py --inventory containers.csv       # Custom inventory file
    python3 scan-containers.py --product-filter openstack       # Filter by product name
    python3 scan-containers.py --reset                          # Reset progress
    python3 scan-containers.py --no-download                    # Force syft scan (skip SBOM download)

Prerequisites:
    - SYFTER_SERVER set to the syfter API endpoint
    - SYFTER_API_KEY set (optional, for authenticated uploads)
    - skopeo available on PATH (or set SKOPEO_BIN)
    - syft available on PATH for fallback scanning (or set SYFT_BIN)
"""

import argparse
import csv
import json
import logging
import os
import random
import shutil
import subprocess
import sys
import tempfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from urllib.parse import urlparse, parse_qs, unquote

from scanner_common import upload_to_syfter, load_progress, save_progress

# ─── Configuration ────────────────────────────────────────────────────────────

PROGRESS_FILE = "scan-progress-containers.json"
DEFAULT_INVENTORY = "container-inventory.csv"
PYXIS_BASE = "https://catalog.redhat.com/api/containers/v1"
PYXIS_CACHE_FILE = "pyxis-discovery-cache.json"
PYXIS_CACHE_TTL = 86400  # 24 hours
SCAN_RETRIES = 3
SCAN_TIMEOUT = 600  # syft can take a while on large images
INSPECT_TIMEOUT = 30
REGISTRY_RETRIES = 3
REGISTRY_BACKOFF_BASE = 10
REGISTRY_BACKOFF_MAX = 120

_registry_lock = threading.Lock()
_registry_min_interval = 0.5  # seconds between registry calls per worker

SYFT_BIN = os.environ.get("SYFT_BIN") or shutil.which("syft") or "syft"
SKOPEO_BIN = os.environ.get("SKOPEO_BIN") or shutil.which("skopeo") or "skopeo"

# Registry auth: syft needs REGISTRY_AUTH_FILE pointing to containers/auth.json
_CONTAINERS_AUTH = os.path.expanduser("~/.config/containers/auth.json")
if not os.environ.get("REGISTRY_AUTH_FILE") and os.path.exists(_CONTAINERS_AUTH):
    os.environ["REGISTRY_AUTH_FILE"] = _CONTAINERS_AUTH


# ─── Pyxis Discovery ─────────────────────────────────────────────────────────

def pyxis_request(path, api_key=None):
    """Make a GET request to the Pyxis API. Returns parsed JSON."""
    from urllib.request import urlopen, Request
    url = f"{PYXIS_BASE}{path}"
    req = Request(url)
    req.add_header("Accept", "application/json")
    if api_key:
        req.add_header("X-API-KEY", api_key)
    with urlopen(req, timeout=30) as resp:
        return json.loads(resp.read().decode())


def pyxis_list_repos(repo_filter=None, registry="registry.access.redhat.com",
                     api_key=None, page_size=100, max_pages=200):
    """List container repositories from Pyxis. Yields (registry, repository, display_name)."""
    from urllib.parse import quote
    page = 0
    while page < max_pages:
        path = f"/repositories?page_size={page_size}&page={page}"
        parts = []
        if repo_filter:
            parts.append(f'repository=regex=".*{repo_filter}.*"')
        if registry:
            parts.append(f'registry=={registry}')
        if parts:
            filt = quote(";".join(parts))
            path += f"&filter={filt}"
        try:
            data = pyxis_request(path, api_key)
        except Exception as e:
            logging.warning(f"  Pyxis page {page} failed: {e}")
            break
        items = data.get("data", [])
        if not items:
            break
        for repo in items:
            r_registry = repo.get("registry", "")
            r_repo = repo.get("repository", "")
            r_name = repo.get("display_data", {}).get("name", r_repo)
            yield r_registry, r_repo, r_name
        if len(items) < page_size:
            break
        page += 1


def pyxis_get_latest_tags(registry, repository, arch="amd64", api_key=None, max_tags=3):
    """Get the latest image tags for a repository from Pyxis."""
    # URL-encode slashes in repository path
    repo_path = repository.replace("/", "%2F") if "/" in repository else repository
    path = (
        f"/repositories/registry/{registry}/repository/{repo_path}"
        f"/images?page_size=20&sort_by=creation_date%5Bdesc%5D"
    )
    try:
        data = pyxis_request(path, api_key)
    except Exception:
        return []

    tags = []
    seen = set()
    for img in data.get("data", []):
        if img.get("architecture") != arch:
            continue
        for repo_entry in img.get("repositories", []):
            for tag_entry in repo_entry.get("tags", []):
                tag = tag_entry.get("name", "")
                if not tag or tag in seen:
                    continue
                # Skip build-specific tags (contain timestamps)
                if len(tag) > 20:
                    continue
                seen.add(tag)
                tags.append(tag)
                if len(tags) >= max_tags:
                    return tags
    return tags


def discover_from_pyxis(repo_filter=None, registry="registry.access.redhat.com",
                        api_key=None, latest_only=True, max_repos=None):
    """Discover container images from Pyxis. Returns inventory list."""
    cache = _load_pyxis_cache()
    if cache:
        logging.info(f"Using Pyxis discovery cache ({len(cache)} images)")
        if max_repos:
            return cache[:max_repos]
        return cache

    logging.info("Discovering images from Pyxis...")
    inventory = []
    repo_count = 0
    for r_registry, r_repo, r_name in pyxis_list_repos(repo_filter, registry, api_key):
        repo_count += 1
        if max_repos and repo_count > max_repos:
            break
        if repo_count % 50 == 0:
            logging.info(f"  Discovered {repo_count} repos, {len(inventory)} images so far...")
        tags = pyxis_get_latest_tags(r_registry, r_repo, api_key=api_key,
                                      max_tags=1 if latest_only else 3)
        if not tags:
            continue
        # Pyxis uses registry.access.redhat.com but images are pulled from registry.redhat.io
        pull_registry = "registry.redhat.io"
        for tag in tags:
            image_ref = f"{pull_registry}/{r_repo}:{tag}"
            product, version = derive_product_info(image_ref)
            inventory.append((image_ref, product, version, r_name))

    logging.info(f"Discovered {len(inventory)} images from {repo_count} repos")
    if not max_repos:
        _save_pyxis_cache(inventory)
    return inventory


def _load_pyxis_cache():
    """Load cached Pyxis discovery results if still valid."""
    if not os.path.exists(PYXIS_CACHE_FILE):
        return None
    try:
        with open(PYXIS_CACHE_FILE) as f:
            data = json.load(f)
        cached_at = data.get("cached_at", 0)
        if time.time() - cached_at > PYXIS_CACHE_TTL:
            return None
        return [tuple(e) for e in data.get("inventory", [])]
    except Exception:
        return None


def _save_pyxis_cache(inventory):
    """Cache Pyxis discovery results."""
    data = {
        "cached_at": time.time(),
        "inventory": inventory,
    }
    with open(PYXIS_CACHE_FILE, "w") as f:
        json.dump(data, f, indent=2)


# ─── Registry Retry ──────────────────────────────────────────────────────────

def _is_transient_error(stderr):
    """Check if a skopeo error is transient (worth retrying)."""
    transient = ["503", "429", "connection reset", "timeout", "EOF",
                 "TLS handshake", "connection refused", "i/o timeout"]
    s = stderr.lower()
    return any(t.lower() in s for t in transient)


def _run_skopeo_with_retry(cmd, timeout=INSPECT_TIMEOUT, label="skopeo"):
    """Run a skopeo command with exponential backoff on transient errors.

    Returns (subprocess.CompletedProcess, None) on success,
    or (None, error_string) on permanent failure or exhausted retries.
    """
    for attempt in range(1, REGISTRY_RETRIES + 1):
        with _registry_lock:
            time.sleep(_registry_min_interval)
        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=timeout
            )
            if result.returncode == 0:
                return result, None
            if not _is_transient_error(result.stderr):
                return None, result.stderr.strip()
            if attempt < REGISTRY_RETRIES:
                wait = min(REGISTRY_BACKOFF_BASE * (2 ** (attempt - 1)),
                           REGISTRY_BACKOFF_MAX)
                wait += random.uniform(0, wait * 0.3)
                logging.debug(f"  {label} transient error, retry {attempt}/{REGISTRY_RETRIES} in {wait:.0f}s")
                time.sleep(wait)
        except subprocess.TimeoutExpired:
            if attempt < REGISTRY_RETRIES:
                wait = min(REGISTRY_BACKOFF_BASE * (2 ** (attempt - 1)),
                           REGISTRY_BACKOFF_MAX)
                logging.debug(f"  {label} timeout, retry {attempt}/{REGISTRY_RETRIES} in {wait:.0f}s")
                time.sleep(wait)
            else:
                return None, "timeout"
    return None, "exhausted retries"


# ─── Image Utilities ─────────────────────────────────────────────────────────

def derive_product_info(image_ref):
    """Derive product name and version from an image reference.

    registry.redhat.io/openshift4/openstack-resource-controller-rhel9:v4.19.0
      -> product_name = openstack-resource-controller-rhel9
      -> product_version = v4.19.0
    """
    ref, _, tag = image_ref.partition(":")
    if not tag:
        tag = "latest"
    # Last path segment is the image name
    name = ref.rsplit("/", 1)[-1]
    return name, tag


def inspect_image(image_ref):
    """Inspect a container image via skopeo with retry on transient errors.

    Returns metadata dict with an added 'ArchDigest' field containing the
    per-architecture manifest digest (needed for SBOM tag derivation).
    The standard 'Digest' field is the manifest list digest for multi-arch images.
    """
    cmd = [
        SKOPEO_BIN, "inspect", f"docker://{image_ref}",
        "--no-tags", "--override-os", "linux", "--override-arch", "amd64",
    ]
    result, err = _run_skopeo_with_retry(cmd, timeout=INSPECT_TIMEOUT, label="inspect")
    if result is None:
        logging.warning(f"  skopeo inspect failed for {image_ref}: {err}")
        return None

    try:
        info = json.loads(result.stdout)
    except (json.JSONDecodeError, ValueError):
        logging.warning(f"  skopeo inspect returned invalid JSON for {image_ref}")
        return None

    raw_cmd = [SKOPEO_BIN, "inspect", "--raw", f"docker://{image_ref}"]
    raw_result, _ = _run_skopeo_with_retry(raw_cmd, timeout=INSPECT_TIMEOUT, label="inspect-raw")
    if raw_result is not None:
        try:
            raw = json.loads(raw_result.stdout)
            for m in raw.get("manifests", []):
                p = m.get("platform", {})
                if p.get("architecture") == "amd64" and p.get("os") == "linux":
                    info["ArchDigest"] = m.get("digest", "")
                    break
        except (json.JSONDecodeError, ValueError):
            pass
    if "ArchDigest" not in info:
        info["ArchDigest"] = info.get("Digest", "")

    return info


def download_sbom(image_ref, manifest_digest):
    """Download Red Hat's official SBOM from the registry.

    Red Hat publishes SPDX 2.3 SBOMs as OCI artifacts at a tag derived
    from the per-arch manifest digest: sha256-<hex>.sbom

    Returns parsed SPDX JSON dict, or None if no SBOM is available.
    """
    if not manifest_digest or not manifest_digest.startswith("sha256:"):
        return None

    sbom_tag = manifest_digest.replace("sha256:", "sha256-") + ".sbom"
    repo = image_ref.rsplit(":", 1)[0]
    sbom_ref = f"{repo}:{sbom_tag}"

    tmpdir = tempfile.mkdtemp(prefix="sbom-")
    try:
        cmd = [
            SKOPEO_BIN, "copy", f"docker://{sbom_ref}", f"dir:{tmpdir}",
        ]
        result, err = _run_skopeo_with_retry(cmd, timeout=INSPECT_TIMEOUT * 2, label="sbom-download")
        if result is None:
            logging.debug(f"  No SBOM artifact at {sbom_tag}: {err}")
            return None

        manifest_path = os.path.join(tmpdir, "manifest.json")
        with open(manifest_path) as f:
            manifest = json.load(f)

        layers = manifest.get("layers", [])
        if not layers:
            return None

        blob_digest = layers[0].get("digest", "")
        if not blob_digest:
            return None

        blob_file = blob_digest.replace("sha256:", "")
        blob_path = os.path.join(tmpdir, blob_file)
        if not os.path.exists(blob_path):
            return None

        with open(blob_path) as f:
            return json.load(f)
    except Exception as e:
        logging.debug(f"  SBOM download failed for {image_ref}: {e}")
        return None
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


def get_layer_chain(image_ref):
    """Get the ordered list of layer digests for a container image.

    Uses skopeo inspect --config to read the image config without pulling
    the full image. Returns list of layer dicts or None on failure.
    """
    cmd = [
        SKOPEO_BIN, "inspect", "--config", f"docker://{image_ref}",
        "--override-os", "linux", "--override-arch", "amd64",
    ]
    result, err = _run_skopeo_with_retry(cmd, timeout=INSPECT_TIMEOUT, label="layer-chain")
    if result is None:
        logging.debug(f"  skopeo inspect --config failed for {image_ref}: {err}")
        return None
    try:
        config = json.loads(result.stdout)
        diff_ids = config.get("rootfs", {}).get("diff_ids", [])
        if not diff_ids:
            return None
        return [
            {"layer_index": i, "layer_id": digest, "source_image": None}
            for i, digest in enumerate(diff_ids)
        ]
    except (json.JSONDecodeError, ValueError):
        return None


def download_attestation(image_ref, manifest_digest):
    """Download cosign attestations (.att) from the registry.

    Red Hat publishes DSSE-envelope attestations as OCI artifacts at a tag
    derived from the per-arch manifest digest: sha256-<hex>.att

    Each attestation layer is a DSSE envelope containing a base64-encoded
    in-toto statement. Returns a list of parsed attestation dicts (one per
    layer), or an empty list if no .att artifact exists.
    """
    if not manifest_digest or not manifest_digest.startswith("sha256:"):
        return []

    att_tag = manifest_digest.replace("sha256:", "sha256-") + ".att"
    repo = image_ref.rsplit(":", 1)[0]
    att_ref = f"{repo}:{att_tag}"

    tmpdir = tempfile.mkdtemp(prefix="att-")
    try:
        cmd = [
            SKOPEO_BIN, "copy", f"docker://{att_ref}", f"dir:{tmpdir}",
        ]
        result, err = _run_skopeo_with_retry(cmd, timeout=INSPECT_TIMEOUT * 4, label="att-download")
        if result is None:
            logging.debug(f"  No attestation at {att_tag}: {err}")
            return []

        manifest_path = os.path.join(tmpdir, "manifest.json")
        with open(manifest_path) as f:
            manifest = json.load(f)

        attestations = []
        for layer in manifest.get("layers", []):
            blob_digest = layer.get("digest", "")
            if not blob_digest:
                continue
            blob_file = blob_digest.replace("sha256:", "")
            blob_path = os.path.join(tmpdir, blob_file)
            if not os.path.exists(blob_path):
                continue
            try:
                with open(blob_path) as f:
                    envelope = json.load(f)
                envelope["_layer_annotations"] = layer.get("annotations", {})
                attestations.append(envelope)
            except (json.JSONDecodeError, OSError):
                continue

        return attestations
    except Exception as e:
        logging.debug(f"  Attestation download failed for {image_ref}: {e}")
        return []
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


def scan_image_syft(image_ref):
    """Fallback: scan a container image with syft. Returns parsed syft-json SBOM."""
    cmd = [
        SYFT_BIN, image_ref, "-o", "syft-json", "--quiet",
        "--platform", "linux/amd64",
    ]
    result = subprocess.run(
        cmd, capture_output=True, text=True, timeout=SCAN_TIMEOUT
    )
    if result.returncode != 0:
        raise RuntimeError(f"syft scan failed: {result.stderr.strip()}")
    return json.loads(result.stdout)


# ─── Package Index ────────────────────────────────────────────────────────────

def _parse_purl(purl):
    """Parse a Package URL into (type, namespace, name, version, qualifiers)."""
    if not purl or ":" not in purl:
        return None, None, None, None, {}
    # pkg:rpm/redhat/openssl@3.5.1-7.el9_7?arch=x86_64&epoch=1&upstream=...
    scheme_rest = purl.split(":", 1)
    if len(scheme_rest) != 2:
        return None, None, None, None, {}
    rest = scheme_rest[1]
    # Split off qualifiers
    qualifiers = {}
    if "?" in rest:
        rest, qs = rest.split("?", 1)
        for pair in qs.split("&"):
            if "=" in pair:
                k, v = pair.split("=", 1)
                qualifiers[k] = unquote(v)
    # Split version
    version = None
    if "@" in rest:
        rest, version = rest.split("@", 1)
    # Split type/namespace/name
    parts = rest.split("/")
    pkg_type = parts[0] if parts else None
    if len(parts) == 3:
        namespace, name = parts[1], parts[2]
    elif len(parts) == 2:
        namespace, name = None, parts[1]
    else:
        namespace, name = None, parts[0] if parts else None
    return pkg_type, namespace, name, version, qualifiers


def build_packages_index_spdx(spdx_sbom, image_ref):
    """Build the packages_json index from a Red Hat SPDX 2.3 SBOM."""
    index = []
    for pkg in spdx_sbom.get("packages", []):
        ext_refs = pkg.get("externalRefs", [])
        purl = ""
        cpes = []
        for ref in ext_refs:
            rtype = ref.get("referenceType", "")
            loc = ref.get("referenceLocator", "")
            if rtype == "purl":
                purl = loc
            elif rtype == "cpe23Type":
                cpes.append(loc)

        if not purl:
            continue

        pkg_type_raw, namespace, purl_name, purl_version, quals = _parse_purl(purl)

        type_map = {"rpm": "rpm", "pypi": "python", "golang": "go-module",
                    "npm": "npm", "gem": "gem"}
        pkg_type = type_map.get(pkg_type_raw, pkg_type_raw or "unknown")

        # Skip OCI image references (container metadata, not software)
        if pkg_type_raw == "oci":
            continue

        name = pkg.get("name", purl_name or "")
        version = purl_version or pkg.get("versionInfo", "")

        license_val = pkg.get("licenseDeclared", "")
        if license_val == "NOASSERTION":
            license_val = ""

        vendor = ""
        originator = pkg.get("originator", "")
        if originator.startswith("Organization: "):
            vendor = originator[len("Organization: "):]

        entry = {
            "name": name,
            "version": version,
            "type": pkg_type,
            "purl": purl,
            "cpes": cpes,
            "license": license_val,
            "source_image": image_ref,
            "layer_id": None,
        }

        if pkg_type == "rpm":
            # Parse release from version: "3.5.1-7.el9_7" -> ver="3.5.1", rel="7.el9_7"
            ver_parts = version.rsplit("-", 1) if "-" in version else [version, ""]
            entry["version"] = ver_parts[0]
            entry["release"] = ver_parts[1] if len(ver_parts) > 1 else ""
            entry["arch"] = quals.get("arch", "")
            epoch_str = quals.get("epoch", "")
            entry["epoch"] = int(epoch_str) if epoch_str else None
            entry["source_rpm"] = quals.get("upstream", "")
            entry["vendor"] = vendor
        else:
            entry["release"] = ""
            entry["arch"] = ""
            entry["epoch"] = None
            entry["source_rpm"] = ""

        index.append(entry)

    return index


def build_container_packages_index(syft_sbom, image_ref, layer_chain=None):
    """Build the packages_json index from a syft SBOM.

    Extracts all artifacts regardless of type (rpm, python, go-module, etc.)
    into the flat package index format syfter expects.
    """
    layer_index_map = {}
    if layer_chain:
        for layer in layer_chain:
            layer_index_map[layer["layer_id"]] = layer["layer_index"]

    index = []
    for artifact in syft_sbom.get("artifacts", []):
        meta = artifact.get("metadata") or {}
        pkg_type = artifact.get("type", "unknown")

        # Extract license from the licenses array
        license_val = ""
        for lic in artifact.get("licenses", []):
            if isinstance(lic, dict):
                license_val = lic.get("spdxExpression") or lic.get("value", "")
            elif isinstance(lic, str):
                license_val = lic
            if license_val:
                break

        # Extract CPEs
        cpes = []
        for cpe_entry in artifact.get("cpes", []):
            if isinstance(cpe_entry, dict):
                cpes.append(cpe_entry.get("cpe", ""))
            elif isinstance(cpe_entry, str):
                cpes.append(cpe_entry)

        # Extract layer ID from first location
        layer_id = None
        locations = artifact.get("locations", [])
        if locations and isinstance(locations[0], dict):
            layer_id = locations[0].get("layerID")

        # Build PURL
        purl = artifact.get("purl", "")

        entry = {
            "name": artifact.get("name", ""),
            "version": artifact.get("version", ""),
            "type": pkg_type,
            "purl": purl,
            "cpes": cpes,
            "license": license_val,
            "source_image": image_ref,
            "layer_id": layer_id,
            "layer_index": layer_index_map.get(layer_id) if layer_id else None,
        }

        # RPM-specific fields
        if pkg_type == "rpm":
            entry["release"] = meta.get("release", "")
            entry["arch"] = meta.get("architecture", "")
            entry["epoch"] = meta.get("epoch")
            entry["source_rpm"] = meta.get("sourceRpm", "")
            entry["vendor"] = meta.get("vendor", "")
        else:
            entry["release"] = ""
            entry["arch"] = ""
            entry["epoch"] = None
            entry["source_rpm"] = ""

        index.append(entry)

    return index


# ─── Layer Enrichment ─────────────────────────────────────────────────────────

_layer_chains_cache = None
_layer_chains_cache_ts = 0


def get_known_layer_chains(server_url):
    """Fetch known layer chains from the server for prefix matching.

    Cached for the lifetime of the scan run (refreshed once per invocation).
    """
    global _layer_chains_cache, _layer_chains_cache_ts
    if _layer_chains_cache is not None and (time.time() - _layer_chains_cache_ts) < 3600:
        return _layer_chains_cache

    parsed = urlparse(server_url)
    clean_url = f"{parsed.scheme}://{parsed.hostname}"
    if parsed.port:
        clean_url += f":{parsed.port}"
    url = f"{clean_url}/api/v1/layers/chains"

    import urllib.request
    req = urllib.request.Request(url)
    api_key = os.environ.get("SYFTER_API_KEY")
    if api_key:
        req.add_header("X-API-Key", api_key)

    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = json.loads(resp.read().decode())
        _layer_chains_cache = {k: v["layers"] for k, v in data.items()}
        _layer_chains_cache_ts = time.time()
        logging.info(f"  Loaded {len(_layer_chains_cache)} layer chains from server")
        return _layer_chains_cache
    except Exception as e:
        logging.debug(f"  Could not fetch layer chains: {e}")
        return {}


def find_base_image(layer_chain, known_chains):
    """Find the base image for a layer chain by prefix matching.

    Returns (base_key, prefix_length) or (None, 0).
    """
    if not layer_chain or not known_chains:
        return None, 0

    chain_ids = [l["layer_id"] for l in layer_chain]
    best_key = None
    best_len = 0

    for key, known_ids in known_chains.items():
        klen = len(known_ids)
        if klen >= len(chain_ids) or klen <= best_len:
            continue
        if chain_ids[:klen] == known_ids:
            best_key = key
            best_len = klen

    return best_key, best_len


def enrich_scan_layers(layer_chain, packages_index, server_url):
    """Enrich layer_chain and packages_index with base image info before upload."""
    if not layer_chain:
        return

    known = get_known_layer_chains(server_url)
    base_key, prefix_len = find_base_image(layer_chain, known)
    if not base_key:
        return

    base_layer_ids = set()
    for i, layer in enumerate(layer_chain):
        if i < prefix_len:
            layer["is_base"] = True
            layer["source_image"] = base_key
            base_layer_ids.add(layer["layer_id"])

    for pkg in packages_index:
        if pkg.get("layer_id") in base_layer_ids:
            pkg["source_image"] = base_key

    logging.info(f"  Enriched: base image {base_key} ({prefix_len} layers)")


# ─── Scanning ─────────────────────────────────────────────────────────────────

def scan_container(image_ref, product, version, description, server_url,
                   manifest_digest=None, no_download=False):
    """Scan a single container image. Returns (status, package_count, message)."""
    sbom = None
    sbom_source = None

    if not no_download and manifest_digest:
        sbom = download_sbom(image_ref, manifest_digest)
        if sbom:
            sbom_source = "redhat-sbom"

    if sbom is None:
        if not no_download and manifest_digest:
            logging.info(f"  No published SBOM, falling back to syft for {product}")
        try:
            sbom = scan_image_syft(image_ref)
            sbom_source = "syft"
        except Exception as e:
            return "failed", 0, f"Scan failed: {e}"

    # Extract container layer chain
    layer_chain = get_layer_chain(image_ref)

    # Download attestations
    attestations = []
    if not no_download and manifest_digest:
        attestations = download_attestation(image_ref, manifest_digest)

    # Detect format and build package index
    if sbom.get("spdxVersion"):
        packages_index = build_packages_index_spdx(sbom, image_ref)
        creators = sbom.get("creationInfo", {}).get("creators", [])
        tools = [c.replace("Tool: ", "") for c in creators if c.startswith("Tool: ")]
        tool_ver = "+".join(tools) if tools else "spdx-sbom"
    else:
        packages_index = build_container_packages_index(sbom, image_ref, layer_chain)
        tool_ver = "syft-" + sbom.get("descriptor", {}).get("version", "unknown")

    if not packages_index:
        return "skipped", 0, "No packages found in image"

    # Enrich with base image info via prefix matching
    enrich_scan_layers(layer_chain, packages_index, server_url)

    try:
        upload_to_syfter(
            server_url, product, version, image_ref,
            sbom, packages_index,
            source_type="container",
            syft_version=tool_ver,
            image_layers=layer_chain,
            attestations=attestations if attestations else None,
        )
        type_counts = {}
        for p in packages_index:
            t = p.get("type", "unknown")
            type_counts[t] = type_counts.get(t, 0) + 1
        type_summary = ", ".join(f"{c} {t}" for t, c in sorted(type_counts.items()))

        extras = []
        if layer_chain:
            extras.append(f"{len(layer_chain)} layers")
        if attestations:
            extras.append(f"{len(attestations)} att")
        extra_str = f" +{', '.join(extras)}" if extras else ""
        return "completed", len(packages_index), f"Uploaded ({type_summary}) [{sbom_source}]{extra_str}"
    except Exception as e:
        return "failed", 0, f"Upload failed: {e}"


# ─── Inventory ────────────────────────────────────────────────────────────────

def load_inventory(inventory_file):
    """Load container image inventory from CSV."""
    entries = []
    with open(inventory_file, newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            image_ref = row.get("image_ref", "").strip()
            if not image_ref:
                continue
            product = row.get("product_name", "").strip()
            version = row.get("product_version", "").strip()
            description = row.get("description", "").strip()
            if not product or not version:
                derived_name, derived_ver = derive_product_info(image_ref)
                product = product or derived_name
                version = version or derived_ver
            entries.append((image_ref, product, version, description))
    return entries


# ─── Main ─────────────────────────────────────────────────────────────────────

def main():
    ap = argparse.ArgumentParser(
        description="Container image scanner for syfter"
    )
    ap.add_argument("--discover-only", action="store_true",
                    help="List images without scanning")
    ap.add_argument("--full", action="store_true",
                    help="Force full rescan (ignore progress)")
    ap.add_argument("--retry-failed", action="store_true",
                    help="Retry previously failed images")
    ap.add_argument("--reset", action="store_true",
                    help="Reset all progress tracking")
    ap.add_argument("--workers", type=int, default=2,
                    help="Number of parallel workers (default: 2)")
    ap.add_argument("--image", type=str,
                    help="Scan a single image by reference")
    ap.add_argument("--inventory", type=str, default=DEFAULT_INVENTORY,
                    help=f"Inventory CSV file (default: {DEFAULT_INVENTORY})")
    ap.add_argument("--product-filter", type=str,
                    help="Only scan images matching this product name substring")
    ap.add_argument("--discover", action="store_true",
                    help="Discover images from Pyxis API instead of inventory file")
    ap.add_argument("--repo-filter", type=str,
                    help="Filter Pyxis repos by name substring (used with --discover)")
    ap.add_argument("--export-inventory", type=str,
                    help="Export discovered images to CSV (used with --discover)")
    ap.add_argument("--no-cache", action="store_true",
                    help="Ignore Pyxis discovery cache")
    ap.add_argument("--max-repos", type=int,
                    help="Limit Pyxis discovery to N repos (for testing)")
    ap.add_argument("--no-download", action="store_true",
                    help="Skip SBOM download, force local syft scan")
    args = ap.parse_args()

    server_url = os.environ.get("SYFTER_SERVER")
    if not server_url and not args.discover_only:
        sys.exit("Error: SYFTER_SERVER not set")

    logging.basicConfig(
        level=logging.INFO,
        format="%(message)s",
        handlers=[
            logging.StreamHandler(),
            logging.FileHandler("scan-containers.log"),
        ],
    )

    # Build the image list
    if args.image:
        product, version = derive_product_info(args.image)
        inventory = [(args.image, product, version, "")]
    elif args.discover:
        if args.no_cache and os.path.exists(PYXIS_CACHE_FILE):
            os.remove(PYXIS_CACHE_FILE)
        api_key = os.environ.get("PYXIS_API_KEY")
        inventory = discover_from_pyxis(
            repo_filter=args.repo_filter,
            api_key=api_key,
            max_repos=args.max_repos,
        )
        if args.export_inventory:
            with open(args.export_inventory, "w", newline="") as f:
                w = csv.writer(f)
                w.writerow(["image_ref", "product_name", "product_version", "description"])
                for ref, prod, ver, desc in inventory:
                    w.writerow([ref, prod, ver, desc])
            logging.info(f"Exported {len(inventory)} images to {args.export_inventory}")
    elif os.path.exists(args.inventory):
        inventory = load_inventory(args.inventory)
    else:
        sys.exit(f"Error: inventory file not found: {args.inventory}")

    if args.product_filter:
        filt = args.product_filter.lower()
        inventory = [(r, p, v, d) for r, p, v, d in inventory if filt in p.lower()]

    if not inventory:
        logging.info("No images to scan.")
        return

    # Progress tracking
    if args.reset and os.path.exists(PROGRESS_FILE):
        os.remove(PROGRESS_FILE)
    progress = load_progress(PROGRESS_FILE)

    if args.retry_failed and progress["failed"]:
        logging.info(f"Retrying {len(progress['failed'])} previously failed images")
        if not args.discover and len(inventory) < len(progress["failed"]):
            logging.info("  Auto-enabling Pyxis discovery to find failed images")
            api_key = os.environ.get("PYXIS_API_KEY")
            inventory = discover_from_pyxis(
                repo_filter=args.repo_filter,
                api_key=api_key,
                max_repos=args.max_repos,
            )
            if args.product_filter:
                filt = args.product_filter.lower()
                inventory = [(r, p, v, d) for r, p, v, d in inventory if filt in p.lower()]
        progress["failed"] = []
        save_progress(progress, PROGRESS_FILE)

    # Discover / inspect phase
    logging.info(f"Inventory: {len(inventory)} images")
    scan_queue = []

    for image_ref, product, version, description in inventory:
        key = f"{product}:{version}"

        if args.discover_only:
            # Just inspect and report
            info = inspect_image(image_ref)
            digest = info.get("Digest", "?") if info else "inspect-failed"
            status = "NEW"
            if key in progress["completed"]:
                stored_digest = progress["timestamps"].get(key, {}).get("digest")
                if stored_digest == digest:
                    status = "DONE"
                else:
                    status = "CHANGED"
            elif key in progress["failed"]:
                status = "FAILED"
            elif key in progress["skipped"]:
                status = "SKIP"
            logging.info(f"[{status}] {product}  {version}  —  {image_ref}  ({digest[:19]})")
            continue

        # Delta check: skip if digest unchanged
        current_digest = None
        arch_digest = None
        if not args.full and key in progress["completed"]:
            info = inspect_image(image_ref)
            if info:
                current_digest = info.get("Digest", "")
                arch_digest = info.get("ArchDigest", current_digest)
                stored_digest = progress["timestamps"].get(key, {}).get("digest")
                if current_digest and current_digest == stored_digest:
                    continue

        # Skip already-completed when not --full
        if not args.full and key in progress["completed"]:
            continue

        scan_queue.append((image_ref, product, version, description, key,
                           current_digest, arch_digest))

    if args.discover_only:
        total = len(inventory)
        done = len(progress["completed"])
        failed = len(progress["failed"])
        logging.info(f"\nSummary: {total} images, {done} completed, {failed} failed")
        return

    if not scan_queue:
        logging.info("All images up to date. Use --full to force rescan.")
        return

    logging.info(f"Scanning {len(scan_queue)} images with {args.workers} workers")
    scan_start = time.time()
    new_completed = 0
    new_failed = 0
    new_skipped = 0

    def process_image(item):
        image_ref, product, version, description, key, digest, arch_digest = item
        if not digest or not arch_digest:
            info = inspect_image(image_ref)
            if info:
                digest = digest or info.get("Digest", "")
                arch_digest = arch_digest or info.get("ArchDigest", digest)
        for attempt in range(1, SCAN_RETRIES + 1):
            try:
                status, pkg_count, msg = scan_container(
                    image_ref, product, version, description, server_url,
                    manifest_digest=arch_digest, no_download=args.no_download,
                )
                return key, image_ref, product, version, status, pkg_count, msg, digest
            except Exception as e:
                if attempt < SCAN_RETRIES:
                    wait = min(REGISTRY_BACKOFF_BASE * (2 ** (attempt - 1)),
                               REGISTRY_BACKOFF_MAX)
                    wait += random.uniform(0, wait * 0.3)
                    logging.warning(f"  Retry {attempt}/{SCAN_RETRIES} for {product}: {e} (waiting {wait:.0f}s)")
                    time.sleep(wait)
                else:
                    return key, image_ref, product, version, "failed", 0, str(e), digest

    def _record_result(key, digest, status, pkg_count, error_msg=None):
        nonlocal new_completed, new_skipped, new_failed
        for lst in ("completed", "skipped", "failed"):
            while key in progress[lst]:
                progress[lst].remove(key)
        progress[status].append(key)
        if status == "completed":
            progress["timestamps"][key] = {
                "digest": digest,
                "scanned_at": datetime.now().isoformat(),
                "package_count": pkg_count,
            }
            new_completed += 1
        elif status == "skipped":
            new_skipped += 1
        else:
            progress.setdefault("failure_reasons", {})[key] = {
                "error": (error_msg or "unknown")[:200],
                "failed_at": datetime.now().isoformat(),
            }
            new_failed += 1
        save_progress(progress, PROGRESS_FILE)

    if args.workers <= 1:
        for i, item in enumerate(scan_queue, 1):
            key, image_ref, product, version, status, pkg_count, msg, digest = process_image(item)
            logging.info(f"[{i}/{len(scan_queue)}] {product} {version}: {status} -- {msg}")
            _record_result(key, digest, status, pkg_count,
                           error_msg=msg if status == "failed" else None)
    else:
        with ThreadPoolExecutor(max_workers=args.workers) as executor:
            futures = {}
            for i, item in enumerate(scan_queue):
                f = executor.submit(process_image, item)
                futures[f] = (i + 1, item)

            for future in as_completed(futures):
                idx, item = futures[future]
                try:
                    key, image_ref, product, version, status, pkg_count, msg, digest = future.result()
                except Exception as e:
                    key = item[4]
                    digest = item[5] or ""
                    status = "failed"
                    msg = str(e)
                    pkg_count = 0

                logging.info(f"[{idx}/{len(scan_queue)}] {item[1]} {item[2]}: {status} -- {msg}")
                _record_result(key, digest, status, pkg_count,
                               error_msg=msg if status == "failed" else None)

    elapsed = time.time() - scan_start
    logging.info(
        f"\nDone in {elapsed/60:.1f}m: "
        f"{new_completed} completed, {new_skipped} skipped, {new_failed} failed"
    )
    total_done = len(progress["completed"])
    total_failed = len(progress["failed"])
    logging.info(f"Overall: {total_done} completed, {total_failed} failed")


if __name__ == "__main__":
    main()
