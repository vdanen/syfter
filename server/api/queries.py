"""
Query API endpoints for searching packages, files, and dependencies.
"""

from typing import List, Optional

from fastapi import APIRouter, Depends, Query
from sqlalchemy import collate, text
from sqlalchemy.orm import Session

from ..db import get_db, Product, Scan, System, Package, File, ImageLayer, Dependency, ComponentRelationship
from .schemas import PackageResponse, FileResponse, StatsResponse, DependencyResponse, ComponentRelationshipResponse
from ..config import get_config

router = APIRouter()


def _apply_like_filter(query, column, pattern: str):
    """Apply a LIKE filter, with exact-match shortcut for non-wildcard patterns.

    Uses LIKE directly so the text_pattern_ops + COLLATE "C" indexes
    can handle both filtering and ORDER BY with early LIMIT termination.
    """
    if not pattern:
        return query

    if "%" not in pattern and "_" not in pattern:
        return query.filter(column == pattern)

    return query.filter(column.like(pattern))


# ============================================================================
# System-based package/file response schemas (inline for now)
# ============================================================================
from pydantic import BaseModel


class SystemPackageResponse(BaseModel):
    """Schema for package search response in system context."""
    id: int
    name: str
    version: Optional[str]
    release: Optional[str]
    arch: Optional[str]
    epoch: Optional[str]
    source_rpm: Optional[str]
    license: Optional[str]
    purl: Optional[str]
    cpes: Optional[str]
    system_hostname: str
    system_tag: Optional[str]

    class Config:
        from_attributes = True


class SystemFileResponse(BaseModel):
    """Schema for file search response in system context."""
    id: int
    path: str
    digest: Optional[str]
    digest_algorithm: Optional[str]
    package_name: str
    package_version: Optional[str]
    system_hostname: str
    system_tag: Optional[str]

    class Config:
        from_attributes = True


@router.get("/packages", response_model=List[PackageResponse])
def search_packages(
    name: Optional[str] = Query(default=None, description="Package name pattern (use % as wildcard)"),
    pkg_version: Optional[str] = Query(default=None, description="Package version pattern (use % as wildcard)"),
    product_name: Optional[str] = Query(default=None, description="Filter by product name"),
    product_version: Optional[str] = Query(default=None, description="Filter by product version"),
    layer_type: Optional[str] = Query(default=None, description="Filter by layer type: 'base' or 'app'"),
    limit: int = Query(default=100, le=1000, description="Maximum results"),
    offset: int = Query(default=0, description="Offset for pagination"),
    db: Session = Depends(get_db),
):
    """Search for packages across all products. Supports layer_type filter for container scans."""
    # Subquery: find matching package IDs with early LIMIT termination.
    # For broad patterns like "lib%" (~500K matches), this lets PostgreSQL
    # use the index to grab just the first N IDs, then JOIN only those.
    inner = db.query(Package.id)

    if product_name or product_version:
        inner = inner.join(Product, Package.product_id == Product.id)
        if product_name:
            inner = inner.filter(Product.name == product_name)
        if product_version:
            inner = inner.filter(Product.version == product_version)

    if layer_type:
        inner = inner.join(
            ImageLayer,
            (Package.layer_id == ImageLayer.layer_id) & (Package.scan_id == ImageLayer.scan_id),
        )
        if layer_type == "base":
            inner = inner.filter(ImageLayer.is_base == True)
        elif layer_type == "app":
            inner = inner.filter(ImageLayer.is_base == False)

    inner = _apply_like_filter(inner, Package.name, name)
    inner = _apply_like_filter(inner, Package.version, pkg_version)
    inner = inner.order_by(collate(Package.name, "C")).offset(offset).limit(limit)
    pkg_ids = inner.subquery()

    results = (
        db.query(Package, Product.name, Product.version)
        .join(pkg_ids, Package.id == pkg_ids.c.id)
        .join(Product, Package.product_id == Product.id)
        .order_by(Package.name)
        .all()
    )

    return [
        PackageResponse(
            id=pkg.id,
            name=pkg.name,
            version=pkg.version,
            release=pkg.release,
            arch=pkg.arch,
            epoch=pkg.epoch,
            source_rpm=pkg.source_rpm,
            license=pkg.license,
            purl=pkg.purl,
            cpes=pkg.cpes,
            product_name=pname,
            product_version=pversion,
            layer_id=pkg.layer_id,
            layer_index=pkg.layer_index,
            source_image=pkg.source_image,
        )
        for pkg, pname, pversion in results
    ]


@router.get("/files", response_model=List[FileResponse])
def search_files(
    path: Optional[str] = Query(default=None, description="File path pattern (use % as wildcard)"),
    digest: Optional[str] = Query(default=None, description="File digest (exact match)"),
    product_name: Optional[str] = Query(default=None, description="Filter by product name"),
    product_version: Optional[str] = Query(default=None, description="Filter by product version"),
    limit: int = Query(default=100, le=1000, description="Maximum results"),
    offset: int = Query(default=0, description="Offset for pagination"),
    db: Session = Depends(get_db),
):
    """Search for files across all products."""
    inner = db.query(File.id)

    if product_name or product_version:
        inner = inner.join(Product, File.product_id == Product.id)
        if product_name:
            inner = inner.filter(Product.name == product_name)
        if product_version:
            inner = inner.filter(Product.version == product_version)

    inner = _apply_like_filter(inner, File.path, path)
    if digest:
        inner = inner.filter(File.digest == digest)
    inner = inner.order_by(collate(File.path, "C")).offset(offset).limit(limit)
    file_ids = inner.subquery()

    results = (
        db.query(File, Package.name, Package.version, Package.source_image, Product.name, Product.version)
        .join(file_ids, File.id == file_ids.c.id)
        .join(Package, File.package_id == Package.id)
        .join(Product, File.product_id == Product.id)
        .order_by(File.path)
        .all()
    )

    return [
        FileResponse(
            id=f.id,
            path=f.path,
            digest=f.digest,
            digest_algorithm=f.digest_algorithm,
            package_name=pkg_name,
            package_version=pkg_version,
            product_name=prod_name,
            product_version=prod_version,
            source_image=source_img,
        )
        for f, pkg_name, pkg_version, source_img, prod_name, prod_version in results
    ]


import time as _time

# In-memory stats cache (avoids 5 COUNT(*) queries on every call)
_stats_cache: dict = {}
_stats_cache_ttl: int = 300  # 5 minutes


def invalidate_stats_cache():
    """Invalidate the stats cache. Call after scan upload/delete."""
    _stats_cache.clear()


@router.get("/stats", response_model=StatsResponse)
def get_stats(db: Session = Depends(get_db)):
    """Get database statistics. Cached for 5 minutes."""
    from ..db import Scan

    config = get_config()

    # Check cache
    cached = _stats_cache.get("stats")
    if cached and (_time.time() - cached["time"]) < _stats_cache_ttl:
        return StatsResponse(
            **cached["data"],
            storage_type=config.storage.type,
            database_type=config.database.type,
        )

    # Use the stats_cache materialized view (refreshed every 5m by CronJob)
    # to avoid 7 COUNT(*) queries across tables with 20M+ rows
    row = db.execute(
        text("SELECT product_count, system_count, scan_count, package_count, "
             "file_count, dependency_count, component_relationship_count "
             "FROM stats_cache LIMIT 1")
    ).first()

    if row:
        data = {
            "products": row.product_count,
            "systems": row.system_count,
            "scans": row.scan_count,
            "packages": row.package_count,
            "files": row.file_count,
            "dependencies": row.dependency_count,
            "component_relationships": row.component_relationship_count,
        }
    else:
        data = {
            "products": 0, "systems": 0, "scans": 0,
            "packages": 0, "files": 0, "dependencies": 0,
            "component_relationships": 0,
        }
    _stats_cache["stats"] = {"time": _time.time(), "data": data}

    return StatsResponse(
        **data,
        storage_type=config.storage.type,
        database_type=config.database.type,
    )


@router.get("/list/packages/{product_name}/{product_version}")
def list_all_packages(
    product_name: str,
    product_version: str,
    limit: int = Query(default=10000, le=100000, description="Maximum results"),
    offset: int = Query(default=0, description="Offset for pagination"),
    db: Session = Depends(get_db),
):
    """
    List all packages for a product version.

    Returns a simple list suitable for piping to grep, etc.
    Includes source_image and layer_id for container scans.
    """
    query = (
        db.query(
            Package.name, Package.version, Package.release, Package.arch,
            Package.source_image, Package.layer_id
        )
        .join(Product, Package.product_id == Product.id)
        .filter(Product.name == product_name, Product.version == product_version)
        .order_by(Package.name)
        .offset(offset)
        .limit(limit)
    )

    return [
        {
            "name": name,
            "version": version,
            "release": release,
            "arch": arch,
            "source_image": source_image,
            "layer_id": layer_id,
        }
        for name, version, release, arch, source_image, layer_id in query.all()
    ]


@router.get("/list/files/{product_name}/{product_version}")
def list_all_files(
    product_name: str,
    product_version: str,
    limit: int = Query(default=10000, le=100000, description="Maximum results"),
    offset: int = Query(default=0, description="Offset for pagination"),
    db: Session = Depends(get_db),
):
    """
    List all file paths for a product version.

    Returns a simple list of file paths suitable for piping to grep, etc.
    """
    query = (
        db.query(File.path)
        .join(Product, File.product_id == Product.id)
        .filter(Product.name == product_name, Product.version == product_version)
        .order_by(File.path)
        .offset(offset)
        .limit(limit)
    )

    return [path for (path,) in query.all()]


# ============================================================================
# Dependency and component queries
# ============================================================================

@router.get("/dependencies", response_model=List[DependencyResponse])
def search_dependencies(
    package_name: Optional[str] = Query(default=None, description="Package name (exact or % wildcard)"),
    dependency_name: Optional[str] = Query(default=None, description="Dependency name (exact or % wildcard)"),
    dependency_type: Optional[str] = Query(default=None, description="'requires' or 'provides'"),
    product_name: Optional[str] = Query(default=None, description="Filter by product name"),
    product_version: Optional[str] = Query(default=None, description="Filter by product version"),
    limit: int = Query(default=100, le=1000, description="Maximum results"),
    offset: int = Query(default=0, description="Offset for pagination"),
    db: Session = Depends(get_db),
):
    """Search dependency records (RPM requires/provides)."""
    from sqlalchemy import select

    query = (
        db.query(Dependency, Package.name, Package.version, Package.arch, Product.name, Product.version)
        .outerjoin(Package, Dependency.package_id == Package.id)
        .join(Product, Dependency.product_id == Product.id)
    )

    if package_name:
        if "%" in package_name or "_" in package_name:
            pkg_ids = select(Package.id).where(Package.name.like(package_name))
        else:
            pkg_ids = select(Package.id).where(Package.name == package_name)
        query = query.filter(Dependency.package_id.in_(pkg_ids))
    if dependency_name:
        query = _apply_like_filter(query, Dependency.dependency_name, dependency_name)
    if dependency_type:
        query = query.filter(Dependency.dependency_type == dependency_type)
    if product_name:
        query = query.filter(Product.name == product_name)
    if product_version:
        query = query.filter(Product.version == product_version)

    results = query.order_by(Dependency.id).offset(offset).limit(limit).all()

    return [
        DependencyResponse(
            id=dep.id,
            package_id=dep.package_id,
            package_name=pkg_name,
            package_version=pkg_version,
            package_arch=pkg_arch,
            dependency_name=dep.dependency_name,
            dependency_version=dep.dependency_version,
            dependency_flags=dep.dependency_flags,
            dependency_type=dep.dependency_type,
            product_name=prod_name,
            product_version=prod_version,
        )
        for dep, pkg_name, pkg_version, pkg_arch, prod_name, prod_version in results
    ]


@router.get("/components", response_model=List[ComponentRelationshipResponse])
def search_components(
    product_name: Optional[str] = Query(default=None, description="Parent product name"),
    component_name: Optional[str] = Query(default=None, description="Component product name"),
    limit: int = Query(default=100, le=1000, description="Maximum results"),
    offset: int = Query(default=0, description="Offset for pagination"),
    db: Session = Depends(get_db),
):
    """Search component relationships between products."""
    from sqlalchemy.orm import aliased

    ParentProduct = aliased(Product)
    ComponentProduct = aliased(Product)

    query = (
        db.query(
            ComponentRelationship,
            ParentProduct.name, ParentProduct.version,
            ComponentProduct.name, ComponentProduct.version,
        )
        .join(ParentProduct, ComponentRelationship.parent_product_id == ParentProduct.id)
        .join(ComponentProduct, ComponentRelationship.component_product_id == ComponentProduct.id)
    )

    if product_name:
        query = query.filter(ParentProduct.name == product_name)
    if component_name:
        query = query.filter(ComponentProduct.name == component_name)

    results = query.offset(offset).limit(limit).all()

    return [
        ComponentRelationshipResponse(
            id=cr.id,
            parent_product_name=p_name,
            parent_product_version=p_version,
            component_product_name=c_name,
            component_product_version=c_version,
            relationship_type=cr.relationship_type,
            created_at=cr.created_at,
        )
        for cr, p_name, p_version, c_name, c_version in results
    ]


@router.get("/provenance/{product_name}/{product_version}")
def get_provenance(
    product_name: str,
    product_version: str,
    package_name_filter: Optional[str] = Query(default=None, description="Filter to specific package name"),
    limit: int = Query(default=100, le=1000, description="Maximum results"),
    db: Session = Depends(get_db),
):
    """Find all products sharing packages with this product, with relationship context."""
    from sqlalchemy.orm import aliased

    product = (
        db.query(Product)
        .filter(Product.name == product_name, Product.version == product_version)
        .first()
    )
    if not product:
        return {"product": product_name, "version": product_version, "shared_packages": []}

    pkg_query = db.query(Package.name, Package.version).filter(Package.product_id == product.id)
    if package_name_filter:
        pkg_query = _apply_like_filter(pkg_query, Package.name, package_name_filter)
    pkg_query = pkg_query.distinct().limit(limit)
    local_packages = pkg_query.all()

    shared = []
    for pkg_name, pkg_version in local_packages:
        other_products = (
            db.query(Product.name, Product.version, Package.arch, Package.source_rpm)
            .join(Package, Package.product_id == Product.id)
            .filter(Package.name == pkg_name, Package.version == pkg_version)
            .filter(Product.id != product.id)
            .distinct()
            .limit(20)
            .all()
        )
        if other_products:
            shared.append({
                "package_name": pkg_name,
                "package_version": pkg_version,
                "found_in": [
                    {"product": p, "version": v, "arch": a, "source_rpm": s}
                    for p, v, a, s in other_products
                ],
            })

    # Enrich with component relationships
    from sqlalchemy.orm import aliased
    ParentProduct = aliased(Product)
    ComponentProduct = aliased(Product)

    relationships = (
        db.query(
            ParentProduct.name, ParentProduct.version,
            ComponentProduct.name, ComponentProduct.version,
            ComponentRelationship.relationship_type,
        )
        .join(ParentProduct, ComponentRelationship.parent_product_id == ParentProduct.id)
        .join(ComponentProduct, ComponentRelationship.component_product_id == ComponentProduct.id)
        .filter(
            (ComponentRelationship.parent_product_id == product.id)
            | (ComponentRelationship.component_product_id == product.id)
        )
        .all()
    )

    return {
        "product": product_name,
        "version": product_version,
        "shared_packages": shared,
        "component_relationships": [
            {
                "parent": {"name": pn, "version": pv},
                "component": {"name": cn, "version": cv},
                "type": rt,
            }
            for pn, pv, cn, cv, rt in relationships
        ],
    }


@router.get("/trace")
def trace_package(
    name: str = Query(..., description="Package name (exact match)"),
    pkg_version: Optional[str] = Query(default=None, description="Version pattern (% wildcard)"),
    limit: int = Query(default=200, le=1000),
    db: Session = Depends(get_db),
):
    """Trace a package across the full product stack (repos -> base images -> layered containers)."""
    from sqlalchemy import and_

    pkg_filter = [Package.name == name]
    if pkg_version:
        if "%" in pkg_version:
            pkg_filter.append(Package.version.like(pkg_version))
        else:
            pkg_filter.append(Package.version == pkg_version)

    from sqlalchemy import func

    hits = (
        db.query(
            Product.name,
            Product.version,
            Package.version,
            Package.arch,
            Package.source_image,
            Scan.source_type,
            Scan.id.label("scan_id"),
        )
        .join(Product, Package.product_id == Product.id)
        .join(Scan, Scan.product_id == Product.id)
        .filter(and_(*pkg_filter))
        .distinct()
        .limit(limit)
        .all()
    )

    # Pre-fetch which scans have base layers (batch to avoid N+1)
    scan_ids = {h.scan_id for h in hits if h.source_type == "container"}
    scans_with_base = set()
    base_source_images = {}
    if scan_ids:
        base_rows = (
            db.query(ImageLayer.scan_id, ImageLayer.source_image)
            .filter(ImageLayer.scan_id.in_(scan_ids), ImageLayer.is_base == True)
            .distinct()
            .all()
        )
        for sid, src in base_rows:
            scans_with_base.add(sid)
            if src:
                base_source_images[sid] = src

    rhel_repos = []
    base_images = []
    layered_containers = []
    other = []

    for hit in hits:
        prod_name, prod_version, pkg_ver, arch, source_image, source_type, scan_id = hit
        entry = {
            "product_name": prod_name,
            "product_version": prod_version,
            "package_version": pkg_ver,
            "arch": arch,
        }

        if source_type == "directory":
            rhel_repos.append(entry)
        elif source_type == "container":
            if scan_id in scans_with_base:
                inherited = base_source_images.get(scan_id, source_image)
                entry["inherited_from"] = inherited
                entry["source_image"] = source_image
                layered_containers.append(entry)
            else:
                entry["source_image"] = source_image
                base_images.append(entry)
        else:
            entry["source_type"] = source_type
            other.append(entry)

    requires = (
        db.query(
            Dependency.dependency_name,
            Dependency.dependency_version,
            Dependency.dependency_flags,
        )
        .join(Package, Dependency.package_id == Package.id)
        .filter(Package.name == name, Dependency.dependency_type == "requires")
        .distinct()
        .limit(100)
        .all()
    )

    required_by = (
        db.query(
            Package.name,
            Package.version,
            Product.name,
        )
        .join(Dependency, Dependency.package_id == Package.id)
        .join(Product, Package.product_id == Product.id)
        .filter(Dependency.dependency_name == name, Dependency.dependency_type == "requires")
        .distinct()
        .limit(100)
        .all()
    )

    return {
        "package_name": name,
        "version_filter": pkg_version,
        "rhel_repos": rhel_repos,
        "base_images": base_images,
        "layered_containers": layered_containers,
        "other": other,
        "requires": [
            {"dependency_name": dn, "dependency_version": dv, "dependency_flags": df}
            for dn, dv, df in requires
        ],
        "required_by": [
            {"package_name": pn, "package_version": pv, "product_name": pr}
            for pn, pv, pr in required_by
        ],
    }


# ============================================================================
# System-based queries (infrastructure mode)
# ============================================================================

@router.get("/systems/packages", response_model=List[SystemPackageResponse])
def search_system_packages(
    name: Optional[str] = Query(default=None, description="Package name pattern (use % as wildcard)"),
    hostname: Optional[str] = Query(default=None, description="Filter by hostname"),
    tag: Optional[str] = Query(default=None, description="Filter by system tag"),
    limit: int = Query(default=100, le=1000, description="Maximum results"),
    offset: int = Query(default=0, description="Offset for pagination"),
    db: Session = Depends(get_db),
):
    """Search for packages across all systems."""
    inner = db.query(Package.id)

    if hostname or tag:
        inner = inner.join(System, Package.system_id == System.id)
        if hostname:
            inner = inner.filter(System.hostname == hostname)
        if tag:
            inner = inner.filter(System.tag == tag)

    inner = _apply_like_filter(inner, Package.name, name)
    inner = inner.order_by(collate(Package.name, "C")).offset(offset).limit(limit)
    pkg_ids = inner.subquery()

    results = (
        db.query(Package, System.hostname, System.tag)
        .join(pkg_ids, Package.id == pkg_ids.c.id)
        .join(System, Package.system_id == System.id)
        .order_by(Package.name)
        .all()
    )

    return [
        SystemPackageResponse(
            id=pkg.id,
            name=pkg.name,
            version=pkg.version,
            release=pkg.release,
            arch=pkg.arch,
            epoch=pkg.epoch,
            source_rpm=pkg.source_rpm,
            license=pkg.license,
            purl=pkg.purl,
            cpes=pkg.cpes,
            system_hostname=hostname,
            system_tag=tag,
        )
        for pkg, hostname, tag in results
    ]


@router.get("/systems/files", response_model=List[SystemFileResponse])
def search_system_files(
    path: Optional[str] = Query(default=None, description="File path pattern (use % as wildcard)"),
    digest: Optional[str] = Query(default=None, description="File digest (exact match)"),
    hostname: Optional[str] = Query(default=None, description="Filter by hostname"),
    tag: Optional[str] = Query(default=None, description="Filter by system tag"),
    limit: int = Query(default=100, le=1000, description="Maximum results"),
    offset: int = Query(default=0, description="Offset for pagination"),
    db: Session = Depends(get_db),
):
    """Search for files across all systems."""
    inner = db.query(File.id)

    if hostname or tag:
        inner = inner.join(System, File.system_id == System.id)
        if hostname:
            inner = inner.filter(System.hostname == hostname)
        if tag:
            inner = inner.filter(System.tag == tag)

    inner = _apply_like_filter(inner, File.path, path)
    if digest:
        inner = inner.filter(File.digest == digest)
    inner = inner.order_by(collate(File.path, "C")).offset(offset).limit(limit)
    file_ids = inner.subquery()

    results = (
        db.query(File, Package.name, Package.version, System.hostname, System.tag)
        .join(file_ids, File.id == file_ids.c.id)
        .join(Package, File.package_id == Package.id)
        .join(System, File.system_id == System.id)
        .order_by(File.path)
        .all()
    )

    return [
        SystemFileResponse(
            id=f.id,
            path=f.path,
            digest=f.digest,
            digest_algorithm=f.digest_algorithm,
            package_name=pkg_name,
            package_version=pkg_version,
            system_hostname=hostname,
            system_tag=tag,
        )
        for f, pkg_name, pkg_version, hostname, tag in results
    ]


@router.get("/systems/list/packages/{hostname}")
def list_system_packages(
    hostname: str,
    limit: int = Query(default=10000, le=100000, description="Maximum results"),
    offset: int = Query(default=0, description="Offset for pagination"),
    db: Session = Depends(get_db),
):
    """
    List all packages for a system.

    Returns a simple list suitable for piping to grep, etc.
    """
    query = (
        db.query(Package.name, Package.version, Package.release, Package.arch)
        .join(System, Package.system_id == System.id)
        .filter(System.hostname == hostname)
        .order_by(Package.name)
        .offset(offset)
        .limit(limit)
    )

    return [
        {
            "name": name,
            "version": version,
            "release": release,
            "arch": arch,
        }
        for name, version, release, arch in query.all()
    ]


@router.get("/systems/list/files/{hostname}")
def list_system_files(
    hostname: str,
    limit: int = Query(default=10000, le=100000, description="Maximum results"),
    offset: int = Query(default=0, description="Offset for pagination"),
    db: Session = Depends(get_db),
):
    """
    List all file paths for a system.

    Returns a simple list of file paths suitable for piping to grep, etc.
    """
    query = (
        db.query(File.path)
        .join(System, File.system_id == System.id)
        .filter(System.hostname == hostname)
        .order_by(File.path)
        .offset(offset)
        .limit(limit)
    )

    return [path for (path,) in query.all()]
