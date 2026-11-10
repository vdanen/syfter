"""
Container layer tracking API endpoints.

Enables queries like:
- "What base image does product X use?"
- "Which packages came from the base image?"
- "Which products consume openssl from their base image?"
- "What did the app layer add on top of the base?"
"""

from typing import List, Optional

import logging
from collections import defaultdict

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import func, distinct, collate, update
from sqlalchemy.orm import Session

from ..db import get_db, Product, Scan, Package, ImageLayer, ComponentRelationship

logger = logging.getLogger(__name__)

router = APIRouter()


# --- Response schemas ---

class LayerResponse(BaseModel):
    layer_id: str
    layer_index: int
    source_image: Optional[str]
    is_base: bool
    command: Optional[str]
    package_count: int = 0

    class Config:
        from_attributes = True


class LayerSummaryResponse(BaseModel):
    product_name: str
    product_version: str
    source_path: str
    source_type: str
    total_layers: int
    base_layers: int
    app_layers: int
    layers: List[LayerResponse]


class LayerPackageResponse(BaseModel):
    id: int
    name: str
    version: Optional[str]
    release: Optional[str]
    arch: Optional[str]
    source_rpm: Optional[str]
    layer_id: Optional[str]
    layer_index: Optional[int]
    source_image: Optional[str]
    is_base: Optional[bool] = None

    class Config:
        from_attributes = True


# --- Endpoints ---
# Static routes must be registered before /{product_name}/{product_version}
# or FastAPI will match "search"/"packages" as product name/version.


@router.get("/search/packages")
def search_packages_by_layer(
    name: Optional[str] = Query(default=None, description="Package name pattern (use % as wildcard)"),
    pkg_version: Optional[str] = Query(default=None, description="Package version pattern"),
    layer_type: Optional[str] = Query(default=None, description="'base' or 'app'"),
    product_name: Optional[str] = Query(default=None, description="Filter by product name"),
    limit: int = Query(default=100, le=1000, description="Maximum results"),
    offset: int = Query(default=0, description="Offset for pagination"),
    db: Session = Depends(get_db),
):
    """
    Search packages across products with layer type filter.

    Example: "Which products ship openssl from their base image?"
      GET /api/v1/layers/search/packages?name=openssl%&layer_type=base
    """
    from .queries import _apply_like_filter

    inner = db.query(Package.id)

    if product_name:
        inner = inner.join(Product, Package.product_id == Product.id)
        inner = inner.filter(Product.name == product_name)

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
        db.query(
            Package.name,
            Package.version,
            Package.arch,
            Package.source_image,
            ImageLayer.is_base,
            Product.name.label("product_name"),
            Product.version.label("product_version"),
        )
        .join(pkg_ids, Package.id == pkg_ids.c.id)
        .join(Product, Package.product_id == Product.id)
        .outerjoin(
            ImageLayer,
            (Package.layer_id == ImageLayer.layer_id) & (Package.scan_id == ImageLayer.scan_id),
        )
        .order_by(Package.name, Product.name)
        .all()
    )

    return [
        {
            "package_name": pkg_name,
            "package_version": pkg_ver,
            "arch": arch,
            "source_image": src_img,
            "is_base": is_base,
            "product_name": prod_name,
            "product_version": prod_ver,
        }
        for pkg_name, pkg_ver, arch, src_img, is_base, prod_name, prod_ver in results
    ]


@router.get("/chains")
def get_layer_chains(
    db: Session = Depends(get_db),
):
    """Return all container layer chains, grouped by product:version."""
    rows = (
        db.query(
            Product.name,
            Product.version,
            ImageLayer.layer_id,
            ImageLayer.layer_index,
            Scan.source_path,
        )
        .join(Scan, ImageLayer.scan_id == Scan.id)
        .join(Product, Scan.product_id == Product.id)
        .order_by(Product.name, Product.version, ImageLayer.layer_index)
        .all()
    )

    chains = {}
    for prod_name, prod_version, layer_id, layer_index, source_path in rows:
        key = f"{prod_name}:{prod_version}"
        if key not in chains:
            chains[key] = {"layers": [], "source_path": source_path}
        chains[key]["layers"].append(layer_id)

    return chains


@router.get("/{product_name}/{product_version}")
def get_layers(
    product_name: str,
    product_version: str,
    db: Session = Depends(get_db),
) -> LayerSummaryResponse:
    """Get container layer chain for a product with package counts per layer."""
    product = (
        db.query(Product)
        .filter(Product.name == product_name, Product.version == product_version)
        .first()
    )
    if not product:
        raise HTTPException(status_code=404, detail="Product not found")

    scan = (
        db.query(Scan)
        .filter(Scan.product_id == product.id)
        .order_by(Scan.scan_timestamp.desc())
        .first()
    )
    if not scan:
        raise HTTPException(status_code=404, detail="No scans found for this product")

    # Get layers with package counts
    layer_counts = (
        db.query(
            ImageLayer,
            func.count(Package.id).label("pkg_count"),
        )
        .outerjoin(Package, Package.layer_id == ImageLayer.layer_id)
        .filter(ImageLayer.scan_id == scan.id)
        .group_by(ImageLayer.id)
        .order_by(ImageLayer.layer_index)
        .all()
    )

    if not layer_counts:
        raise HTTPException(status_code=404, detail="No layer information available (not a container scan)")

    layers = [
        LayerResponse(
            layer_id=layer.layer_id,
            layer_index=layer.layer_index,
            source_image=layer.source_image,
            is_base=layer.is_base,
            command=layer.command,
            package_count=pkg_count,
        )
        for layer, pkg_count in layer_counts
    ]

    base_count = sum(1 for l in layers if l.is_base)

    return LayerSummaryResponse(
        product_name=product.name,
        product_version=product.version,
        source_path=scan.source_path,
        source_type=scan.source_type,
        total_layers=len(layers),
        base_layers=base_count,
        app_layers=len(layers) - base_count,
        layers=layers,
    )


@router.get("/{product_name}/{product_version}/packages")
def get_layer_packages(
    product_name: str,
    product_version: str,
    layer_type: Optional[str] = Query(
        default=None,
        description="Filter by layer type: 'base' or 'app'",
    ),
    limit: int = Query(default=1000, le=10000, description="Maximum results"),
    offset: int = Query(default=0, description="Offset for pagination"),
    db: Session = Depends(get_db),
) -> List[LayerPackageResponse]:
    """
    List packages for a product, optionally filtered by layer type.

    - layer_type=base: packages from the base image only
    - layer_type=app: packages added by the application layer
    - omit layer_type: all packages with layer attribution
    """
    product = (
        db.query(Product)
        .filter(Product.name == product_name, Product.version == product_version)
        .first()
    )
    if not product:
        raise HTTPException(status_code=404, detail="Product not found")

    query = (
        db.query(Package, ImageLayer.is_base)
        .outerjoin(
            ImageLayer,
            (Package.layer_id == ImageLayer.layer_id) & (Package.scan_id == ImageLayer.scan_id),
        )
        .filter(Package.product_id == product.id)
    )

    if layer_type == "base":
        query = query.filter(ImageLayer.is_base == True)
    elif layer_type == "app":
        query = query.filter(ImageLayer.is_base == False)

    query = query.order_by(Package.name).offset(offset).limit(limit)
    results = query.all()

    return [
        LayerPackageResponse(
            id=pkg.id,
            name=pkg.name,
            version=pkg.version,
            release=pkg.release,
            arch=pkg.arch,
            source_rpm=pkg.source_rpm,
            layer_id=pkg.layer_id,
            layer_index=pkg.layer_index,
            source_image=pkg.source_image,
            is_base=is_base,
        )
        for pkg, is_base in results
    ]


@router.get("/{product_name}/{product_version}/base-image")
def get_base_image(
    product_name: str,
    product_version: str,
    db: Session = Depends(get_db),
):
    """Get the base image(s) used by a product."""
    product = (
        db.query(Product)
        .filter(Product.name == product_name, Product.version == product_version)
        .first()
    )
    if not product:
        raise HTTPException(status_code=404, detail="Product not found")

    scan = (
        db.query(Scan)
        .filter(Scan.product_id == product.id)
        .order_by(Scan.scan_timestamp.desc())
        .first()
    )
    if not scan:
        raise HTTPException(status_code=404, detail="No scans found")

    base_images = (
        db.query(distinct(ImageLayer.source_image))
        .filter(ImageLayer.scan_id == scan.id, ImageLayer.is_base == True)
        .all()
    )

    return {
        "product_name": product.name,
        "product_version": product.version,
        "base_images": [img for (img,) in base_images if img],
    }


@router.post("/enrich")
def enrich_layers(
    db: Session = Depends(get_db),
):
    """Batch-enrich container layers using prefix matching to identify base images.

    For each container product, finds the shortest layer chain from another product
    that is a strict prefix. Marks matching layers as is_base=True and sets
    source_image to the base product reference.
    """
    rows = (
        db.query(
            Product.name,
            Product.version,
            ImageLayer.layer_id,
            ImageLayer.layer_index,
            ImageLayer.scan_id,
            Scan.source_path,
        )
        .join(Scan, ImageLayer.scan_id == Scan.id)
        .join(Product, Scan.product_id == Product.id)
        .order_by(Product.name, Product.version, ImageLayer.layer_index)
        .all()
    )

    # Build per-product layer chains
    product_chains = {}  # key -> {layers: [layer_id, ...], scan_id, source_path}
    for prod_name, prod_version, layer_id, layer_index, scan_id, source_path in rows:
        key = f"{prod_name}:{prod_version}"
        if key not in product_chains:
            product_chains[key] = {
                "layers": [],
                "scan_id": scan_id,
                "source_path": source_path,
            }
        product_chains[key]["layers"].append(layer_id)

    # For each product, find the shortest strict prefix match
    enriched = 0
    base_images_found = set()
    skipped = 0
    packages_updated = 0
    layers_updated = 0

    # Sort candidates by chain length (shortest first) for efficient prefix matching
    candidates = sorted(product_chains.items(), key=lambda x: len(x[1]["layers"]))

    for key, chain_data in product_chains.items():
        chain = chain_data["layers"]
        if len(chain) < 2:
            skipped += 1
            continue

        best_base = None
        best_base_len = 0

        for cand_key, cand_data in candidates:
            if cand_key == key:
                continue
            cand_chain = cand_data["layers"]
            cand_len = len(cand_chain)

            if cand_len >= len(chain):
                continue
            if cand_len <= best_base_len:
                continue

            # Check if candidate is a prefix
            if chain[:cand_len] == cand_chain:
                best_base = cand_key
                best_base_len = cand_len

        if not best_base:
            skipped += 1
            continue

        base_images_found.add(best_base)
        base_layers = set(chain[:best_base_len])
        scan_id = chain_data["scan_id"]

        # Update ImageLayer records
        layer_result = db.execute(
            update(ImageLayer)
            .where(ImageLayer.scan_id == scan_id, ImageLayer.layer_id.in_(base_layers))
            .values(is_base=True, source_image=best_base)
        )

        # Update Package records -- only if packages have layer_id set
        # (SPDX-sourced packages have layer_id=NULL; for those, use
        # ImageLayer.is_base at query time instead)
        pkg_result = db.execute(
            update(Package)
            .where(Package.scan_id == scan_id, Package.layer_id.in_(base_layers))
            .values(source_image=best_base)
        )

        # If no packages matched by layer_id, try matching by scan_id + layer_index
        # for packages that have layer_index set
        if pkg_result.rowcount == 0:
            # Fall back: mark packages whose layer_index falls within the base range
            pkg_result = db.execute(
                update(Package)
                .where(
                    Package.scan_id == scan_id,
                    Package.layer_index.isnot(None),
                    Package.layer_index < best_base_len,
                )
                .values(source_image=best_base)
            )

        enriched += 1
        packages_updated += pkg_result.rowcount
        layers_updated += layer_result.rowcount

    db.commit()

    logger.info(
        f"Layer enrichment: {enriched} products enriched, "
        f"{len(base_images_found)} base images found, {skipped} skipped, "
        f"{layers_updated} layer rows updated, {packages_updated} package rows updated"
    )

    return {
        "enriched_products": enriched,
        "base_images_found": sorted(base_images_found),
        "skipped": skipped,
        "total_products": len(product_chains),
        "layers_updated": layers_updated,
        "packages_updated": packages_updated,
    }


import re

_RHEL_SUFFIX_RE = re.compile(r"-rhel-?(\d+)")


def _infer_base_name(product_name: str) -> Optional[str]:
    """Infer base image family from product name. Returns None if unknown or IS a base image."""
    name_lower = product_name.lower()
    if name_lower.startswith(("ubi9", "ubi8", "ubi7", "ubi10")):
        return None  # this IS a base image
    m = _RHEL_SUFFIX_RE.search(name_lower)
    if m:
        ver = m.group(1)
        if "minimal" in name_lower:
            return f"ubi{ver}-minimal"
        return f"ubi{ver}"
    return None


@router.get("/{product_name}/{product_version}/ancestry")
def get_ancestry(
    product_name: str,
    product_version: str,
    db: Session = Depends(get_db),
):
    """Get the full parent image ancestry chain for a container product.

    Recursively follows build_tool relationships to walk the full image
    heritage: layered-image -> base-image -> micro-image -> scratch.
    Falls back to name-based inference when no build_tool relationship exists.
    """
    product = (
        db.query(Product)
        .filter(Product.name == product_name, Product.version == product_version)
        .first()
    )
    if not product:
        raise HTTPException(status_code=404, detail="Product not found")

    ancestry = [{
        "product_name": product.name,
        "product_version": product.version,
        "depth": 0,
        "source": "self",
    }]

    visited = {product.id}
    current_id = product.id
    resolution_method = "none"
    max_depth = 10

    for depth in range(1, max_depth + 1):
        rel = (
            db.query(ComponentRelationship)
            .filter(
                ComponentRelationship.parent_product_id == current_id,
                ComponentRelationship.relationship_type == "build_tool",
            )
            .first()
        )

        if rel and rel.component_product_id not in visited:
            parent = db.query(Product).filter(Product.id == rel.component_product_id).first()
            if parent:
                visited.add(parent.id)
                ancestry.append({
                    "product_name": parent.name,
                    "product_version": parent.version,
                    "depth": depth,
                    "source": "build_tool",
                })
                current_id = parent.id
                resolution_method = "build_tool"
                continue

        # Fallback: name-based inference (one level only)
        if depth == 1:
            current_product = db.query(Product).filter(Product.id == current_id).first()
            if current_product:
                inferred = _infer_base_name(current_product.name)
                if inferred:
                    base = (
                        db.query(Product)
                        .filter(Product.name == inferred)
                        .order_by(Product.version.desc())
                        .first()
                    )
                    if base and base.id not in visited:
                        visited.add(base.id)
                        ancestry.append({
                            "product_name": base.name,
                            "product_version": base.version,
                            "depth": depth,
                            "source": "name_inference",
                        })
                        current_id = base.id
                        resolution_method = "name_inference"
                        continue
        break

    return {
        "product_name": product_name,
        "product_version": product_version,
        "ancestry": ancestry,
        "total_depth": len(ancestry) - 1,
        "resolution_method": resolution_method,
    }
