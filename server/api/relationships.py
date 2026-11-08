"""
Component relationship API endpoints.
"""

import gzip
import json
import logging
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session, aliased

from ..auth import require_write
from ..db import get_db, Product, Scan, ComponentRelationship
from ..storage import get_storage
from .schemas import ComponentRelationshipCreate, ComponentRelationshipResponse

logger = logging.getLogger(__name__)

router = APIRouter()


@router.get("/", response_model=List[ComponentRelationshipResponse])
def list_relationships(
    parent_name: Optional[str] = Query(default=None, description="Filter by parent product name"),
    component_name: Optional[str] = Query(default=None, description="Filter by component product name"),
    relationship_type: Optional[str] = Query(default=None, description="Filter by type: layered, maintained, build_tool"),
    limit: int = Query(default=100, le=1000),
    offset: int = Query(default=0),
    db: Session = Depends(get_db),
):
    """List component relationships with optional filters.

    Use component_name to find all products that depend on a given base image
    (reverse ancestry). Use parent_name to find what a product is built from.
    """
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

    if parent_name:
        query = query.filter(ParentProduct.name == parent_name)
    if component_name:
        query = query.filter(ComponentProduct.name == component_name)
    if relationship_type:
        query = query.filter(ComponentRelationship.relationship_type == relationship_type)

    results = query.offset(offset).limit(limit).all()

    return [
        ComponentRelationshipResponse(
            id=cr.id,
            parent_product_name=pn,
            parent_product_version=pv,
            component_product_name=cn,
            component_product_version=cv,
            relationship_type=cr.relationship_type,
            created_at=cr.created_at,
        )
        for cr, pn, pv, cn, cv in results
    ]


@router.post("/", response_model=ComponentRelationshipResponse, status_code=201, dependencies=[Depends(require_write)])
def create_relationship(
    body: ComponentRelationshipCreate,
    db: Session = Depends(get_db),
):
    """Create a component relationship between two products."""
    parent = (
        db.query(Product)
        .filter(Product.name == body.parent_product_name, Product.version == body.parent_product_version)
        .first()
    )
    if not parent:
        raise HTTPException(
            status_code=404,
            detail=f"Parent product {body.parent_product_name}-{body.parent_product_version} not found",
        )

    component = (
        db.query(Product)
        .filter(Product.name == body.component_product_name, Product.version == body.component_product_version)
        .first()
    )
    if not component:
        raise HTTPException(
            status_code=404,
            detail=f"Component product {body.component_product_name}-{body.component_product_version} not found",
        )

    if body.relationship_type not in ("layered", "maintained", "build_tool"):
        raise HTTPException(
            status_code=400,
            detail="relationship_type must be 'layered', 'maintained', or 'build_tool'",
        )

    existing = (
        db.query(ComponentRelationship)
        .filter(
            ComponentRelationship.parent_product_id == parent.id,
            ComponentRelationship.component_product_id == component.id,
        )
        .first()
    )
    if existing:
        raise HTTPException(
            status_code=409,
            detail="Relationship already exists between these products",
        )

    cr = ComponentRelationship(
        parent_product_id=parent.id,
        component_product_id=component.id,
        relationship_type=body.relationship_type,
    )
    db.add(cr)
    db.commit()
    db.refresh(cr)

    return ComponentRelationshipResponse(
        id=cr.id,
        parent_product_name=parent.name,
        parent_product_version=parent.version,
        component_product_name=component.name,
        component_product_version=component.version,
        relationship_type=cr.relationship_type,
        created_at=cr.created_at,
    )


@router.delete("/{relationship_id}", status_code=204, dependencies=[Depends(require_write)])
def delete_relationship(relationship_id: int, db: Session = Depends(get_db)):
    """Delete a component relationship."""
    cr = db.query(ComponentRelationship).filter(ComponentRelationship.id == relationship_id).first()
    if not cr:
        raise HTTPException(status_code=404, detail="Relationship not found")

    db.delete(cr)
    db.commit()


def _extract_spdx_build_tools(sbom: dict) -> list:
    """Extract BUILD_TOOL_OF base image names from an SPDX 2.3 SBOM."""
    if not sbom.get("spdxVersion"):
        return []

    packages_by_id = {p["SPDXID"]: p for p in sbom.get("packages", [])}

    described_id = None
    for rel in sbom.get("relationships", []):
        if rel.get("relationshipType") == "DESCRIBES":
            described_id = rel.get("relatedSpdxElement")
            break

    bases = []
    for rel in sbom.get("relationships", []):
        if rel.get("relationshipType") != "BUILD_TOOL_OF":
            continue
        if described_id and rel.get("relatedSpdxElement") != described_id:
            continue

        tool_pkg = packages_by_id.get(rel.get("spdxElementId"))
        if not tool_pkg:
            continue

        for ref in tool_pkg.get("externalRefs", []):
            if ref.get("referenceType") == "purl" and ref.get("referenceLocator", "").startswith("pkg:oci/"):
                bases.append(tool_pkg.get("name", ""))
                break

    return bases


@router.post("/backfill", dependencies=[Depends(require_write)])
def backfill_build_tool_relationships(
    db: Session = Depends(get_db),
):
    """Back-populate build_tool relationships from SPDX BUILD_TOOL_OF data in S3.

    Scans all container-type SBOMs stored in S3, extracts BUILD_TOOL_OF
    relationships from SPDX 2.3 data, and creates build_tool component
    relationships for each discovered base image reference.
    """
    storage = get_storage()

    container_scans = (
        db.query(Scan.id, Scan.original_sbom_key, Scan.product_id)
        .filter(Scan.source_type == "container")
        .all()
    )

    id_to_product = {}
    name_to_ids = {}
    for p in db.query(Product.id, Product.name, Product.version).all():
        id_to_product[p.id] = (p.name, p.version)
        name_to_ids.setdefault(p.name, []).append((p.version, p.id))

    existing_rels = set()
    for cr in db.query(ComponentRelationship.parent_product_id, ComponentRelationship.component_product_id).all():
        existing_rels.add((cr.parent_product_id, cr.component_product_id))

    created = 0
    skipped_no_sbom = 0
    skipped_not_spdx = 0
    skipped_no_bases = 0
    skipped_exists = 0
    skipped_product_missing = 0
    errors = 0

    total_scans = len(container_scans)
    logger.info(f"Backfill: processing {total_scans} container scans")

    for idx, (scan_id, sbom_key, product_id) in enumerate(container_scans):
        if idx > 0 and idx % 500 == 0:
            logger.info(f"Backfill: {idx}/{total_scans} scans processed, {created} relationships created")
        if not sbom_key:
            skipped_no_sbom += 1
            continue

        try:
            sbom = storage.get_json(sbom_key, compressed=True)
        except Exception as e:
            if errors < 5:
                logger.warning(f"Backfill: error reading {sbom_key}: {e}")
            errors += 1
            continue

        if not sbom.get("spdxVersion"):
            skipped_not_spdx += 1
            continue

        bases = _extract_spdx_build_tools(sbom)
        if not bases:
            skipped_no_bases += 1
            continue

        if product_id not in id_to_product:
            errors += 1
            continue

        for base_name in bases:
            candidates = name_to_ids.get(base_name, [])
            if not candidates:
                base_product_id = None
            else:
                base_product_id = max(candidates, key=lambda x: x[0])[1]

            if not base_product_id:
                skipped_product_missing += 1
                continue

            if (product_id, base_product_id) in existing_rels:
                skipped_exists += 1
                continue

            cr = ComponentRelationship(
                parent_product_id=product_id,
                component_product_id=base_product_id,
                relationship_type="build_tool",
            )
            db.add(cr)
            existing_rels.add((product_id, base_product_id))
            created += 1

    db.commit()

    logger.info(
        f"Backfill: {created} relationships created, "
        f"{skipped_exists} already existed, "
        f"{skipped_product_missing} base products not in DB, "
        f"{errors} errors"
    )

    return {
        "created": created,
        "scans_processed": len(container_scans),
        "skipped_no_sbom": skipped_no_sbom,
        "skipped_not_spdx": skipped_not_spdx,
        "skipped_no_bases": skipped_no_bases,
        "skipped_exists": skipped_exists,
        "skipped_product_missing": skipped_product_missing,
        "errors": errors,
    }
