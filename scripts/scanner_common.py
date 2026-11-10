"""
scanner_common.py -- Shared utilities for syfter scanners.

Used by scan-repodata.py and scan-containers.py.
"""

import gzip
import json
import logging
import os
import subprocess
import tempfile
import time
from urllib.parse import urlparse


UPLOAD_RETRIES = 3
UPLOAD_BACKOFF_BASE = 15
HEALTH_CHECK_INTERVAL = 15
HEALTH_CHECK_MAX_WAIT = 600


def wait_for_healthy_server(server_url):
    """Block until the server health endpoint returns 200.

    Checks every HEALTH_CHECK_INTERVAL seconds, up to HEALTH_CHECK_MAX_WAIT.
    Returns True if healthy, False if timed out.
    """
    parsed = urlparse(server_url)
    clean_url = f"{parsed.scheme}://{parsed.hostname}"
    if parsed.port:
        clean_url += f":{parsed.port}"
    health_url = f"{clean_url}/health"

    deadline = time.time() + HEALTH_CHECK_MAX_WAIT
    warned = False

    while time.time() < deadline:
        try:
            result = subprocess.run(
                ["curl", "-sk", "-o", "/dev/null", "-w", "%{http_code}",
                 "--max-time", "5", health_url],
                capture_output=True, text=True, timeout=10,
            )
            if result.stdout.strip() == "200":
                if warned:
                    logging.info("  Server is healthy again, resuming")
                return True
        except Exception:
            pass

        if not warned:
            logging.warning("  Server unhealthy, waiting for recovery...")
            warned = True
        time.sleep(HEALTH_CHECK_INTERVAL)

    logging.error(f"  Server not healthy after {HEALTH_CHECK_MAX_WAIT}s, giving up")
    return False


def upload_to_syfter(server_url, product, version, source_path,
                     original_sbom, packages_index, dependencies_index=None,
                     source_type="directory", syft_version="repodata-scanner-1.0",
                     image_layers=None, attestations=None):
    """Upload a scan to the syfter server using curl with retry on transient errors."""

    # Health-gate: confirm the server is up before sending a large payload
    if not wait_for_healthy_server(server_url):
        raise RuntimeError("Server unhealthy, aborting upload")

    original_gz = gzip.compress(json.dumps(original_sbom).encode())
    # Send a minimal modified_sbom stub -- it's identical to original anyway,
    # and decompressing two copies of a large SBOM OOMs the server.
    modified_gz = gzip.compress(b'{"stub": true}')
    packages_gz = gzip.compress(json.dumps(packages_index).encode())
    deps_gz = gzip.compress(json.dumps(dependencies_index).encode()) if dependencies_index else None
    layers_gz = gzip.compress(json.dumps(image_layers).encode()) if image_layers else None
    att_gz = gzip.compress(json.dumps(attestations).encode()) if attestations else None

    parsed = urlparse(server_url)
    clean_url = f"{parsed.scheme}://{parsed.hostname}"
    if parsed.port:
        clean_url += f":{parsed.port}"
    url = f"{clean_url}/api/v1/scans/upload"

    tmp_files = []
    try:
        for data in [original_gz, modified_gz, packages_gz]:
            f = tempfile.NamedTemporaryFile(suffix=".gz", delete=False)
            f.write(data)
            f.close()
            tmp_files.append(f.name)

        cmd = [
            "curl", "-sk", url,
            "-w", "\n%{http_code}",
            "-F", f"product_name={product}",
            "-F", f"product_version={version}",
            "-F", f"source_path={source_path}",
            "-F", f"source_type={source_type}",
            "-F", f"syft_version={syft_version}",
            "-F", f"original_sbom=@{tmp_files[0]};type=application/gzip",
            "-F", f"modified_sbom=@{tmp_files[1]};type=application/gzip",
            "-F", f"packages_json=@{tmp_files[2]};type=application/gzip",
        ]

        for gz_data, field_name in [
            (deps_gz, "dependencies_json"),
            (layers_gz, "image_layers_json"),
            (att_gz, "attestation_json"),
        ]:
            if gz_data:
                f = tempfile.NamedTemporaryFile(suffix=".gz", delete=False)
                f.write(gz_data)
                f.close()
                tmp_files.append(f.name)
                cmd.extend(["-F", f"{field_name}=@{f.name};type=application/gzip"])

        api_key = os.environ.get("SYFTER_API_KEY")
        if api_key:
            cmd.extend(["-H", f"X-API-Key: {api_key}"])
        elif parsed.username:
            cmd.extend(["-u", f"{parsed.username}:{parsed.password or ''}"])

        last_err = None
        for attempt in range(1, UPLOAD_RETRIES + 1):
            try:
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            except subprocess.TimeoutExpired:
                last_err = RuntimeError("curl timed out (300s)")
                if attempt < UPLOAD_RETRIES:
                    wait = UPLOAD_BACKOFF_BASE * attempt
                    logging.warning(f"  Upload timeout, retry {attempt}/{UPLOAD_RETRIES} in {wait}s")
                    time.sleep(wait)
                continue

            if result.returncode != 0:
                last_err = RuntimeError(f"curl failed: {result.stderr}")
                if attempt < UPLOAD_RETRIES:
                    wait = UPLOAD_BACKOFF_BASE * attempt
                    logging.warning(f"  Upload curl error, retry {attempt}/{UPLOAD_RETRIES} in {wait}s")
                    time.sleep(wait)
                continue

            lines = result.stdout.rsplit("\n", 1)
            body = lines[0] if len(lines) > 1 else result.stdout
            http_code = int(lines[-1]) if len(lines) > 1 and lines[-1].strip().isdigit() else 0

            if http_code >= 500 or http_code == 0:
                last_err = RuntimeError(f"HTTP {http_code}: {body[:200]}")
                if attempt < UPLOAD_RETRIES:
                    # Server error -- wait for it to recover before retrying
                    if not wait_for_healthy_server(server_url):
                        raise RuntimeError("Server unhealthy after upload failure, aborting")
                continue

            if http_code == 429:
                retry_after = UPLOAD_BACKOFF_BASE * attempt * 2
                last_err = RuntimeError(f"Rate limited (429)")
                if attempt < UPLOAD_RETRIES:
                    logging.warning(f"  Rate limited, retry {attempt}/{UPLOAD_RETRIES} in {retry_after}s")
                    time.sleep(retry_after)
                continue

            if http_code >= 400:
                raise RuntimeError(f"HTTP {http_code}: {body[:500]}")

            resp_data = json.loads(body)
            return resp_data

        raise last_err or RuntimeError("Upload failed after retries")
    finally:
        for path in tmp_files:
            try:
                os.unlink(path)
            except OSError:
                pass


def load_progress(progress_file):
    """Load scan progress from a JSON file."""
    if os.path.exists(progress_file):
        with open(progress_file) as f:
            data = json.load(f)
        data.setdefault("completed", [])
        data.setdefault("failed", [])
        data.setdefault("skipped", [])
        data.setdefault("timestamps", {})
        return data
    return {"completed": [], "failed": [], "skipped": [], "timestamps": {}}


def save_progress(progress, progress_file):
    """Atomically save scan progress to a JSON file."""
    tmp = progress_file + ".tmp"
    with open(tmp, "w") as f:
        json.dump(progress, f, indent=2)
    os.replace(tmp, progress_file)
