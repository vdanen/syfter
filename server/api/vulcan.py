"""
VULCAN CVE impact analysis with container layer deduplication.

Implements the Updated VULCAN proposal: given a vulnerable RPM component,
find all affected products, attribute packages to container layers, and
deduplicate tracker recommendations to the lowest-layer image.
"""

import json
from collections import defaultdict
from datetime import datetime
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import and_
from sqlalchemy.orm import Session

from ..auth import require_write
from ..db import (
    get_db,
    ComponentRelationship,
    ImageLayer,
    Package,
    Product,
    Scan,
    VulcanAnalysis,
    VulcanTracker,
)
from .schemas import (
    VulcanAnalyzeRequest,
    VulcanAnalysisListItem,
    VulcanAnalysisResponse,
    VulcanAnalysisSummary,
    VulcanResolveRequest,
    VulcanTrackerResponse,
)

router = APIRouter()

import re

_BASE_IMAGE_PATTERNS = [
    (re.compile(r"^ubi9-minimal[:\-]"), "ubi9-minimal"),
    (re.compile(r"^ubi9[:\-]"), "ubi9"),
    (re.compile(r"^ubi8-minimal[:\-]"), "ubi8-minimal"),
    (re.compile(r"^ubi8[:\-]"), "ubi8"),
    (re.compile(r"^ubi7[:\-]"), "ubi7"),
]

_RHEL_SUFFIX_RE = re.compile(r"-rhel-?(\d+)")


def _infer_base_image(product_name: str) -> Optional[str]:
    """Infer the base image family from a container product name.

    Returns a base image key like 'ubi9' or None if unknown.
    Layer digest matching is unreliable across rebuilds, so we use
    naming conventions that cover ~85% of Red Hat container images.
    """
    name_lower = product_name.lower()
    for pattern, base in _BASE_IMAGE_PATTERNS:
        if pattern.match(name_lower):
            return None  # this IS a base image, not layered

    m = _RHEL_SUFFIX_RE.search(name_lower)
    if m:
        ver = m.group(1)
        if "minimal" in name_lower:
            return f"ubi{ver}-minimal"
        return f"ubi{ver}"

    return None


def _run_analysis(component: str, ps_module: Optional[str], db: Session):
    """Core dedup engine: find affected products, categorize by layer, deduplicate."""

    pkg_filter = [Package.name == component]

    hits = (
        db.query(
            Product.id,
            Product.name,
            Product.version,
            Product.ps_module,
            Package.version,
            Package.arch,
            Package.layer_id,
            Package.source_image,
            Scan.source_type,
            Scan.id.label("scan_id"),
        )
        .join(Product, Package.product_id == Product.id)
        .join(Scan, Scan.product_id == Product.id)
        .filter(and_(*pkg_filter))
        .distinct()
        .all()
    )

    if ps_module:
        hits = [h for h in hits if h.ps_module and h.ps_module.startswith(ps_module)]

    if not hits:
        return {
            "rhel_repos": [],
            "base_images": [],
            "layered": [],
            "app_layer": [],
        }

    scan_ids = {h.scan_id for h in hits if h.source_type == "container"}
    base_layer_map = {}
    base_source_map = {}
    if scan_ids:
        base_rows = (
            db.query(ImageLayer.scan_id, ImageLayer.layer_id, ImageLayer.source_image)
            .filter(ImageLayer.scan_id.in_(scan_ids), ImageLayer.is_base == True)
            .all()
        )
        for sid, lid, src in base_rows:
            base_layer_map.setdefault(sid, set()).add(lid)
            if src:
                base_source_map[sid] = src

    scans_with_base = set(base_layer_map.keys())

    # Build build_tool relationship map: product_id -> base product name
    container_product_ids = {h[0] for h in hits if h[8] == "container"}
    build_tool_map = {}
    if container_product_ids:
        bt_rows = (
            db.query(
                ComponentRelationship.parent_product_id,
                Product.name,
                Product.version,
            )
            .join(Product, ComponentRelationship.component_product_id == Product.id)
            .filter(
                ComponentRelationship.parent_product_id.in_(container_product_ids),
                ComponentRelationship.relationship_type == "build_tool",
            )
            .all()
        )
        for parent_id, comp_name, comp_version in bt_rows:
            build_tool_map[parent_id] = f"{comp_name}:{comp_version}"

    # Build first-layer digest groups for fallback inference:
    # if a named -rhelN image shares its first layer with an unnamed image,
    # we can infer they share the same base.
    first_layer_base = {}
    if scan_ids:
        first_rows = (
            db.query(ImageLayer.scan_id, ImageLayer.layer_id)
            .filter(ImageLayer.scan_id.in_(scan_ids), ImageLayer.layer_index == 0)
            .all()
        )
        scan_first_layer = {sid: lid for sid, lid in first_rows}

        digest_to_base = {}
        for hit in hits:
            sid = hit.scan_id
            if hit[8] == "container" and sid in scan_first_layer:
                inferred = _infer_base_image(hit[1])
                if inferred:
                    digest_to_base.setdefault(scan_first_layer[sid], inferred)

        for sid, fl_digest in scan_first_layer.items():
            if fl_digest in digest_to_base:
                first_layer_base[sid] = digest_to_base[fl_digest]

    rhel_repos = []
    base_images = []
    layered = []
    app_layer = []

    seen = set()
    for hit in hits:
        prod_id, prod_name, prod_version, prod_ps_module, pkg_ver, arch, layer_id, source_image, source_type, scan_id = hit
        key = (prod_name, prod_version)
        if key in seen:
            continue
        seen.add(key)

        entry = {
            "product_name": prod_name,
            "product_version": prod_version,
            "package_version": pkg_ver,
            "package_arch": arch,
            "ps_module": prod_ps_module,
        }

        if source_type == "directory":
            rhel_repos.append(entry)
        elif source_type == "container":
            # Priority 1: build_tool relationship (authoritative, from SPDX BUILD_TOOL_OF)
            if prod_id in build_tool_map:
                entry["base_source"] = build_tool_map[prod_id]
                layered.append(entry)
            # Priority 2: layer-based categorization (when is_base is populated)
            elif scan_id in scans_with_base:
                if layer_id and layer_id in base_layer_map.get(scan_id, set()):
                    entry["base_source"] = base_source_map.get(scan_id, source_image)
                    layered.append(entry)
                else:
                    app_layer.append(entry)
            else:
                # Priority 3: name-based + digest-based inference
                inferred = _infer_base_image(prod_name)
                if inferred is None and scan_id in first_layer_base:
                    inferred = first_layer_base[scan_id]

                if inferred:
                    entry["base_source"] = inferred
                    layered.append(entry)
                else:
                    base_images.append(entry)
        else:
            rhel_repos.append(entry)

    return {
        "rhel_repos": rhel_repos,
        "base_images": base_images,
        "layered": layered,
        "app_layer": app_layer,
    }


def _build_trackers(categorized: dict):
    """Generate deduplicated tracker recommendations from categorized hits."""
    trackers = []

    for entry in categorized["base_images"]:
        trackers.append({
            "tracker_type": "base_image",
            "product_name": entry["product_name"],
            "product_version": entry["product_version"],
            "package_version": entry["package_version"],
            "package_arch": entry["package_arch"],
            "covers_count": 0,
            "covered_products": [],
        })

    base_groups = defaultdict(list)
    for entry in categorized["layered"]:
        base_key = entry.get("base_source", "unknown")
        base_groups[base_key].append(f"{entry['product_name']}:{entry['product_version']}")

    for base_tracker in trackers:
        if base_tracker["tracker_type"] == "base_image":
            bt_key = f"{base_tracker['product_name']}:{base_tracker['product_version']}"
            for base_source, children in base_groups.items():
                if base_source and (
                    base_tracker["product_name"] in base_source
                    or bt_key == base_source
                ):
                    base_tracker["covers_count"] = len(children)
                    base_tracker["covered_products"] = sorted(children)

    matched_sources = set()
    for base_tracker in trackers:
        if base_tracker["covers_count"] > 0:
            for base_source in base_groups:
                if base_tracker["product_name"] in (base_source or ""):
                    matched_sources.add(base_source)

    for base_source, children in base_groups.items():
        if base_source not in matched_sources:
            base_name = base_source.rsplit("/", 1)[-1] if base_source else "unknown"
            base_name = base_name.split(":")[0] if ":" in base_name else base_name
            trackers.append({
                "tracker_type": "base_image",
                "product_name": base_name,
                "product_version": "(unscanned)",
                "package_version": None,
                "package_arch": None,
                "covers_count": len(children),
                "covered_products": sorted(children),
            })

    for entry in categorized["app_layer"]:
        trackers.append({
            "tracker_type": "app_layer",
            "product_name": entry["product_name"],
            "product_version": entry["product_version"],
            "package_version": entry["package_version"],
            "package_arch": entry["package_arch"],
            "covers_count": 1,
            "covered_products": [],
        })

    return trackers


@router.post("/analyze", response_model=VulcanAnalysisResponse, status_code=201, dependencies=[Depends(require_write)])
def analyze(body: VulcanAnalyzeRequest, db: Session = Depends(get_db)):
    """Run a VULCAN CVE impact analysis with layer deduplication."""

    categorized = _run_analysis(body.component, body.ps_module, db)
    tracker_recs = _build_trackers(categorized)

    n_rhel = len(categorized["rhel_repos"])
    n_base = len(categorized["base_images"])
    n_layered = len(categorized["layered"])
    n_app = len(categorized["app_layer"])
    n_total = n_rhel + n_base + n_layered + n_app
    n_trackers = len(tracker_recs)

    analysis = VulcanAnalysis(
        cve_id=body.cve_id,
        component=body.component,
        ps_module=body.ps_module,
        impact=body.impact,
        total_products=n_total,
        rhel_repos=n_rhel,
        base_images=n_base,
        layered_containers=n_layered,
        app_layer_unique=n_app,
        recommended_trackers=n_trackers,
    )
    db.add(analysis)
    db.flush()

    db_trackers = []
    for rec in tracker_recs:
        vt = VulcanTracker(
            analysis_id=analysis.id,
            tracker_type=rec["tracker_type"],
            product_name=rec["product_name"],
            product_version=rec["product_version"],
            covers_count=rec["covers_count"],
            covered_products_json=json.dumps(rec["covered_products"]),
            package_version=rec.get("package_version"),
            package_arch=rec.get("package_arch"),
        )
        db.add(vt)
        db_trackers.append(vt)

    db.commit()
    db.refresh(analysis)
    for vt in db_trackers:
        db.refresh(vt)

    if n_total > 0:
        ratio = f"{n_total} -> {n_trackers} ({100 * (1 - n_trackers / n_total):.1f}% reduction)"
    else:
        ratio = "0 -> 0"

    return VulcanAnalysisResponse(
        id=analysis.id,
        cve_id=analysis.cve_id,
        component=analysis.component,
        ps_module=analysis.ps_module,
        impact=analysis.impact,
        analyzed_at=analysis.analyzed_at,
        status=analysis.status,
        summary=VulcanAnalysisSummary(
            total_products=n_total,
            rhel_repos=n_rhel,
            base_images=n_base,
            layered_containers=n_layered,
            app_layer_unique=n_app,
            recommended_trackers=n_trackers,
            dedup_ratio=ratio,
        ),
        trackers=[
            VulcanTrackerResponse(
                id=vt.id,
                tracker_type=vt.tracker_type,
                product_name=vt.product_name,
                product_version=vt.product_version,
                covers_count=vt.covers_count,
                covered_products=json.loads(vt.covered_products_json or "[]"),
                package_version=vt.package_version,
                package_arch=vt.package_arch,
                status=vt.status,
            )
            for vt in db_trackers
        ],
    )


@router.get("/analyses", response_model=List[VulcanAnalysisListItem])
def list_analyses(
    status: Optional[str] = Query(default=None, description="Filter by status"),
    cve_id: Optional[str] = Query(default=None, description="Filter by CVE ID"),
    component: Optional[str] = Query(default=None, description="Filter by component"),
    limit: int = Query(default=50, le=500),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
):
    """List VULCAN analyses."""
    query = db.query(VulcanAnalysis)
    if status:
        query = query.filter(VulcanAnalysis.status == status)
    if cve_id:
        query = query.filter(VulcanAnalysis.cve_id == cve_id)
    if component:
        query = query.filter(VulcanAnalysis.component == component)

    results = (
        query.order_by(VulcanAnalysis.analyzed_at.desc())
        .offset(offset)
        .limit(limit)
        .all()
    )

    return [
        VulcanAnalysisListItem(
            id=a.id,
            cve_id=a.cve_id,
            component=a.component,
            ps_module=a.ps_module,
            impact=a.impact,
            analyzed_at=a.analyzed_at,
            status=a.status,
            total_products=a.total_products,
            recommended_trackers=a.recommended_trackers,
        )
        for a in results
    ]


@router.get("/analyses/{analysis_id}", response_model=VulcanAnalysisResponse)
def get_analysis(analysis_id: int, db: Session = Depends(get_db)):
    """Get a VULCAN analysis with full tracker detail."""
    analysis = db.query(VulcanAnalysis).filter(VulcanAnalysis.id == analysis_id).first()
    if not analysis:
        raise HTTPException(status_code=404, detail="Analysis not found")

    n_total = analysis.total_products
    n_trackers = analysis.recommended_trackers
    if n_total > 0:
        ratio = f"{n_total} -> {n_trackers} ({100 * (1 - n_trackers / n_total):.1f}% reduction)"
    else:
        ratio = "0 -> 0"

    return VulcanAnalysisResponse(
        id=analysis.id,
        cve_id=analysis.cve_id,
        component=analysis.component,
        ps_module=analysis.ps_module,
        impact=analysis.impact,
        analyzed_at=analysis.analyzed_at,
        status=analysis.status,
        resolved_at=analysis.resolved_at,
        resolved_by=analysis.resolved_by,
        summary=VulcanAnalysisSummary(
            total_products=analysis.total_products,
            rhel_repos=analysis.rhel_repos,
            base_images=analysis.base_images,
            layered_containers=analysis.layered_containers,
            app_layer_unique=analysis.app_layer_unique,
            recommended_trackers=analysis.recommended_trackers,
            dedup_ratio=ratio,
        ),
        trackers=[
            VulcanTrackerResponse(
                id=vt.id,
                tracker_type=vt.tracker_type,
                product_name=vt.product_name,
                product_version=vt.product_version,
                covers_count=vt.covers_count,
                covered_products=json.loads(vt.covered_products_json or "[]"),
                package_version=vt.package_version,
                package_arch=vt.package_arch,
                status=vt.status,
            )
            for vt in analysis.trackers
        ],
    )


@router.post("/analyses/{analysis_id}/resolve", status_code=200, dependencies=[Depends(require_write)])
def resolve_analysis(
    analysis_id: int,
    body: VulcanResolveRequest,
    db: Session = Depends(get_db),
):
    """Mark a VULCAN analysis and its trackers as resolved."""
    analysis = db.query(VulcanAnalysis).filter(VulcanAnalysis.id == analysis_id).first()
    if not analysis:
        raise HTTPException(status_code=404, detail="Analysis not found")
    if analysis.status == "resolved":
        raise HTTPException(status_code=409, detail="Analysis already resolved")

    now = datetime.utcnow()
    analysis.status = "resolved"
    analysis.resolved_at = now
    analysis.resolved_by = body.resolved_by

    open_trackers = (
        db.query(VulcanTracker)
        .filter(VulcanTracker.analysis_id == analysis_id, VulcanTracker.status == "open")
        .all()
    )
    for vt in open_trackers:
        vt.status = "resolved"
        vt.resolved_at = now
        vt.resolved_by = body.resolved_by

    db.commit()

    return {
        "id": analysis.id,
        "status": "resolved",
        "resolved_at": now.isoformat(),
        "resolved_by": body.resolved_by,
        "trackers_resolved": len(open_trackers),
    }


@router.delete("/analyses/{analysis_id}", status_code=204, dependencies=[Depends(require_write)])
def delete_analysis(analysis_id: int, db: Session = Depends(get_db)):
    """Delete a VULCAN analysis and its trackers."""
    analysis = db.query(VulcanAnalysis).filter(VulcanAnalysis.id == analysis_id).first()
    if not analysis:
        raise HTTPException(status_code=404, detail="Analysis not found")

    db.delete(analysis)
    db.commit()
