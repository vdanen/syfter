"""
OSIDB client for vulnerability correlation.

Queries the Red Hat OSIDB API for unresolved CVE affects matching
components from syfter product scans.
"""

import json
import os
import re
import ssl
import threading
import time
import urllib.parse
import urllib.request


ENVS = {
    "prod": os.getenv("OSIDB_URL", "https://osidb.prodsec.redhat.com"),
    "uat": os.getenv("OSIDB_UAT_URL", "https://osidb-uat.prodsec.redhat.com"),
}

OPEN_RESOLUTIONS = {"", "FIX", "DEFER"}

EL_RE = re.compile(r"\.el(\d+)")

_SSL_CTX = None


def _get_ssl_ctx():
    global _SSL_CTX
    if _SSL_CTX is None:
        _SSL_CTX = ssl.create_default_context()
    return _SSL_CTX


def _fetch_json(url, retries=3):
    ctx = _get_ssl_ctx()
    for attempt in range(retries):
        try:
            req = urllib.request.Request(url)
            with urllib.request.urlopen(req, context=ctx, timeout=180) as resp:
                return json.load(resp)
        except Exception:
            if attempt < retries - 1:
                time.sleep(2 ** attempt)
            else:
                raise


def _paginate(url_template, page_size=200):
    offset = 0
    while True:
        data = _fetch_json(url_template.format(limit=page_size, offset=offset))
        yield from data["results"]
        offset += page_size
        if offset >= data["count"]:
            break


class OsidbCache:
    """File-based cache for OSIDB affect queries, keyed on (module, component)."""

    def __init__(self, cache_dir=None, ttl=3600):
        self._ttl = ttl
        if cache_dir:
            self._dir = cache_dir
        else:
            self._dir = os.path.expanduser("~/.cache/syfter")
        self._path = os.path.join(self._dir, "osidb_cache.json")
        self._lock = threading.Lock()
        self._data = self._load()
        self._dirty = False

    def _load(self):
        try:
            with open(self._path) as f:
                data = json.load(f)
            if data.get("version") != 1:
                return {"version": 1, "entries": {}}
            return data
        except (FileNotFoundError, json.JSONDecodeError, ValueError):
            return {"version": 1, "entries": {}}

    def save(self):
        if not self._dirty:
            return
        os.makedirs(self._dir, exist_ok=True)
        now = time.time()
        max_age = self._ttl * 2
        pruned = {k: v for k, v in self._data["entries"].items()
                  if now - v.get("timestamp", 0) < max_age}
        self._data["entries"] = pruned
        tmp = self._path + ".tmp"
        with open(tmp, "w") as f:
            json.dump(self._data, f)
        os.replace(tmp, self._path)

    def get(self, module, component):
        key = f"{module}::{component}"
        entry = self._data["entries"].get(key)
        if entry is None:
            return None
        if time.time() - entry.get("timestamp", 0) > self._ttl:
            return None
        return entry["affects"]

    def put(self, module, component, affects):
        key = f"{module}::{component}"
        with self._lock:
            self._data["entries"][key] = {
                "timestamp": time.time(),
                "affects": affects,
            }
            self._dirty = True


def get_affects(base_url, module, component):
    """Query OSIDB for open affects on a component."""
    url_template = (
        f"{base_url}/osidb/api/v1/affects?"
        f"ps_module={urllib.parse.quote(module)}"
        f"&ps_component={urllib.parse.quote(component)}"
        f"&include_fields=uuid,flaw,ps_module,ps_component,affectedness,resolution,impact"
        f"&limit={{limit}}&offset={{offset}}"
    )
    affects = []
    for a in _paginate(url_template):
        if a.get("affectedness") == "NOTAFFECTED":
            continue
        if a.get("resolution", "") not in OPEN_RESOLUTIONS:
            continue
        affects.append(a)
    return affects


def get_affects_cached(base_url, module, component, cache):
    """Query with optional caching."""
    if cache:
        cached = cache.get(module, component)
        if cached is not None:
            return cached
    affects = get_affects(base_url, module, component)
    if cache:
        cache.put(module, component, affects)
    return affects


def get_flaws_batch(base_url, uuids):
    """Fetch flaw details for a batch of UUIDs."""
    flaws = {}
    uuid_param = ",".join(uuids)
    url_template = (
        f"{base_url}/osidb/api/v1/flaws?"
        f"uuid__in={uuid_param}"
        f"&include_fields=uuid,cve_id,title,impact,workflow_state,source,cvss_scores"
        f"&limit={{limit}}&offset={{offset}}"
    )
    try:
        for flaw in _paginate(url_template, page_size=100):
            if flaw.get("workflow_state") == "REJECTED":
                continue
            flaws[flaw["uuid"]] = flaw
    except Exception:
        pass
    return flaws


def get_rh_cvss(flaw):
    """Extract Red Hat CVSS score (V4 preferred over V3 over V2)."""
    scores = flaw.get("cvss_scores", [])
    rh_scores = [s for s in scores if s.get("issuer") == "RH"]
    if not rh_scores:
        if scores:
            return max(float(s["score"]) for s in scores)
        return None
    for ver in ["V4", "V3", "V2"]:
        for s in rh_scores:
            if s.get("version") == ver:
                return float(s["score"])
    return float(rh_scores[0]["score"])


def detect_module(packages):
    """Auto-detect OSIDB ps_module from package release strings (.elN)."""
    el_counts = {}
    for pkg in packages:
        version = pkg.get("version", "") or ""
        release = pkg.get("release", "") or ""
        for text in [version, release]:
            m = EL_RE.search(text)
            if m:
                ver = m.group(1)
                el_counts[ver] = el_counts.get(ver, 0) + 1
    if not el_counts:
        return None
    majority = max(el_counts, key=el_counts.get)
    return f"rhel-{majority}"
