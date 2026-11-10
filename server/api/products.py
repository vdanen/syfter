"""
Product API endpoints.
"""

import json
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Response
from sqlalchemy import func, text
from sqlalchemy.orm import Session

from ..auth import require_write
from ..db import get_db, Product, Scan, Package, File, ImageLayer, Attestation
from .schemas import ProductCreate, ProductResponse, ProductUpdate

router = APIRouter()


@router.get("/", response_model=List[ProductResponse])
def list_products(
    response: Response,
    limit: int = Query(default=100, le=1000, description="Maximum results"),
    offset: int = Query(default=0, description="Offset for pagination"),
    name: Optional[str] = Query(default=None, description="Filter by product name (case-insensitive substring, or use % as wildcard)"),
    tag: Optional[str] = Query(default=None, description="Filter to products with scans matching this tag"),
    db: Session = Depends(get_db),
):
    """List all products with scan, package, and file counts."""
    where_clauses = []
    params = {"limit": limit, "offset": offset}
    if name:
        if "%" in name:
            params["name"] = name.lower()
        else:
            params["name"] = f"%{name.lower()}%"
        where_clauses.append("LOWER(name) LIKE :name")
    if tag:
        params["tag"] = tag
        where_clauses.append(
            "id IN (SELECT s.product_id FROM scans s "
            "JOIN scan_tags st ON st.scan_id = s.id "
            "JOIN tags t ON t.id = st.tag_id WHERE t.name = :tag)"
        )
    name_filter = ("WHERE " + " AND ".join(where_clauses)) if where_clauses else ""

    sql = text(f"""
        WITH filtered AS (
            SELECT id FROM products
            {name_filter}
            ORDER BY name, version
            LIMIT :limit OFFSET :offset
        ),
        total AS (
            SELECT count(*) AS cnt FROM products
            {name_filter}
        )
        SELECT p.id, p.name, p.version, p.vendor, p.cpe_vendor,
               p.cpe_product, p.purl_namespace, p.description, p.created_at,
               p.ps_update_stream, p.ps_module,
               COALESCE(sc.cnt, 0) AS scan_count,
               COALESCE(pc.cnt, 0) AS total_packages,
               COALESCE(fc.cnt, 0) AS total_files,
               total.cnt AS _total
        FROM products p
        JOIN filtered ON p.id = filtered.id
        CROSS JOIN total
        LEFT JOIN LATERAL (SELECT count(*) cnt FROM scans WHERE product_id = p.id) sc ON true
        LEFT JOIN LATERAL (SELECT count(*) cnt FROM packages WHERE product_id = p.id) pc ON true
        LEFT JOIN LATERAL (SELECT count(*) cnt FROM files WHERE product_id = p.id) fc ON true
        ORDER BY p.name, p.version
    """)

    results = db.execute(sql, params).fetchall()

    if results:
        response.headers["X-Total-Count"] = str(results[0]._total)
    else:
        response.headers["X-Total-Count"] = "0"

    return [
        ProductResponse(
            id=row.id,
            name=row.name,
            version=row.version,
            vendor=row.vendor,
            cpe_vendor=row.cpe_vendor,
            cpe_product=row.cpe_product,
            purl_namespace=row.purl_namespace,
            description=row.description,
            ps_update_stream=row.ps_update_stream,
            ps_module=row.ps_module,
            created_at=row.created_at,
            scan_count=row.scan_count,
            total_packages=row.total_packages,
            total_files=row.total_files,
        )
        for row in results
    ]


@router.get("/{product_name}/{product_version}", response_model=ProductResponse)
def get_product(product_name: str, product_version: str, db: Session = Depends(get_db)):
    """Get a specific product with counts."""
    product = (
        db.query(Product)
        .filter(Product.name == product_name, Product.version == product_version)
        .first()
    )

    if not product:
        raise HTTPException(status_code=404, detail="Product not found")

    scan_count = db.query(func.count(Scan.id)).filter(Scan.product_id == product.id).scalar() or 0
    total_packages = db.query(func.count(Package.id)).filter(Package.product_id == product.id).scalar() or 0
    total_files = db.query(func.count(File.id)).filter(File.product_id == product.id).scalar() or 0

    return ProductResponse(
        id=product.id,
        name=product.name,
        version=product.version,
        vendor=product.vendor,
        cpe_vendor=product.cpe_vendor,
        cpe_product=product.cpe_product,
        purl_namespace=product.purl_namespace,
        description=product.description,
        ps_update_stream=product.ps_update_stream,
        ps_module=product.ps_module,
        created_at=product.created_at,
        scan_count=scan_count,
        total_packages=total_packages,
        total_files=total_files,
    )


@router.post("/", response_model=ProductResponse, status_code=201, dependencies=[Depends(require_write)])
def create_product(product: ProductCreate, db: Session = Depends(get_db)):
    """Create a new product."""
    existing = (
        db.query(Product)
        .filter(Product.name == product.name, Product.version == product.version)
        .first()
    )
    if existing:
        raise HTTPException(status_code=409, detail="Product already exists")

    db_product = Product(
        name=product.name,
        version=product.version,
        vendor=product.vendor,
        cpe_vendor=product.cpe_vendor,
        cpe_product=product.cpe_product or product.name,
        purl_namespace=product.purl_namespace,
        description=product.description,
        ps_update_stream=product.ps_update_stream,
        ps_module=product.ps_module,
    )
    db.add(db_product)
    db.commit()
    db.refresh(db_product)

    return ProductResponse(
        id=db_product.id,
        name=db_product.name,
        version=db_product.version,
        vendor=db_product.vendor,
        cpe_vendor=db_product.cpe_vendor,
        cpe_product=db_product.cpe_product,
        purl_namespace=db_product.purl_namespace,
        description=db_product.description,
        ps_update_stream=db_product.ps_update_stream,
        ps_module=db_product.ps_module,
        created_at=db_product.created_at,
        scan_count=0,
        total_packages=0,
        total_files=0,
    )


@router.get("/{product_name}/{product_version}/layers")
def get_product_layers(product_name: str, product_version: str, db: Session = Depends(get_db)):
    """Get container layer chain for a product (for container scans only)."""
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

    if not scan.image_layers_json:
        raise HTTPException(status_code=404, detail="No layer information available (not a container scan)")

    layers = json.loads(scan.image_layers_json)
    return {
        "product_name": product.name,
        "product_version": product.version,
        "source_path": scan.source_path,
        "source_type": scan.source_type,
        "layers": layers,
    }


@router.get("/{product_name}/{product_version}/attestations")
def get_product_attestations(product_name: str, product_version: str, db: Session = Depends(get_db)):
    """Get cosign attestation metadata for a product (container scans only)."""
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

    atts = db.query(Attestation).filter(Attestation.scan_id == scan.id).all()
    if not atts:
        raise HTTPException(status_code=404, detail="No attestation data available")

    return {
        "product_name": product.name,
        "product_version": product.version,
        "source_path": scan.source_path,
        "attestations": [
            {
                "id": a.id,
                "predicate_type": a.predicate_type,
                "builder_id": a.builder_id,
                "build_type": a.build_type,
                "build_started_on": a.build_started_on.isoformat() if a.build_started_on else None,
                "build_finished_on": a.build_finished_on.isoformat() if a.build_finished_on else None,
            }
            for a in atts
        ],
    }


@router.patch("/{product_name}/{product_version}", dependencies=[Depends(require_write)])
def update_product(
    product_name: str,
    product_version: str,
    body: ProductUpdate,
    db: Session = Depends(get_db),
):
    """Rename or update a product's metadata."""
    product = (
        db.query(Product)
        .filter(Product.name == product_name, Product.version == product_version)
        .first()
    )
    if not product:
        raise HTTPException(status_code=404, detail="Product not found")

    if body.name is not None:
        existing = (
            db.query(Product)
            .filter(
                Product.name == body.name,
                Product.version == (body.version or product.version),
                Product.id != product.id,
            )
            .first()
        )
        if existing:
            raise HTTPException(status_code=409, detail="A product with that name/version already exists")
        product.name = body.name

    if body.version is not None:
        existing = (
            db.query(Product)
            .filter(
                Product.name == (body.name or product.name),
                Product.version == body.version,
                Product.id != product.id,
            )
            .first()
        )
        if existing:
            raise HTTPException(status_code=409, detail="A product with that name/version already exists")
        product.version = body.version

    if body.description is not None:
        product.description = body.description
    if body.ps_update_stream is not None:
        product.ps_update_stream = body.ps_update_stream
    if body.ps_module is not None:
        product.ps_module = body.ps_module

    db.commit()
    db.refresh(product)

    scan_count = db.query(func.count(Scan.id)).filter(Scan.product_id == product.id).scalar() or 0
    pkg_count = db.query(func.count(Package.id)).filter(Package.product_id == product.id).scalar() or 0

    return {
        "id": product.id,
        "name": product.name,
        "version": product.version,
        "vendor": product.vendor,
        "cpe_vendor": product.cpe_vendor,
        "cpe_product": product.cpe_product,
        "purl_namespace": product.purl_namespace,
        "description": product.description,
        "ps_update_stream": product.ps_update_stream,
        "ps_module": product.ps_module,
        "created_at": product.created_at,
        "scan_count": scan_count,
        "total_packages": pkg_count,
        "total_files": 0,
    }


@router.delete("/{product_name}/{product_version}", status_code=204, dependencies=[Depends(require_write)])
def delete_product(product_name: str, product_version: str, db: Session = Depends(get_db)):
    """Delete a product and all its scans, packages, and files."""
    product = (
        db.query(Product)
        .filter(Product.name == product_name, Product.version == product_version)
        .first()
    )
    if not product:
        raise HTTPException(status_code=404, detail="Product not found")

    product_id = product.id

    # Clean up S3 objects (SBOMs + attestations) before deleting DB rows
    from ..storage import get_storage
    storage = get_storage()
    scans = db.query(Scan).filter(Scan.product_id == product_id).all()
    for scan in scans:
        try:
            storage.delete(scan.original_sbom_key)
            storage.delete(scan.modified_sbom_key)
        except Exception:
            pass
        for att in db.query(Attestation).filter(Attestation.scan_id == scan.id).all():
            try:
                storage.delete(att.attestation_key)
            except Exception:
                pass

    # Delete in FK-safe order
    db.execute(text("DELETE FROM dependencies WHERE product_id = :product_id"), {"product_id": product_id})
    db.execute(text("DELETE FROM component_relationships WHERE parent_product_id = :product_id OR component_product_id = :product_id"), {"product_id": product_id})
    db.execute(text("DELETE FROM files WHERE product_id = :product_id"), {"product_id": product_id})
    db.execute(text("DELETE FROM packages WHERE product_id = :product_id"), {"product_id": product_id})
    db.execute(text("""
        DELETE FROM scan_tags WHERE scan_id IN (
            SELECT id FROM scans WHERE product_id = :product_id
        )
    """), {"product_id": product_id})
    db.execute(text("""
        DELETE FROM image_layers WHERE scan_id IN (
            SELECT id FROM scans WHERE product_id = :product_id
        )
    """), {"product_id": product_id})
    db.execute(text("""
        DELETE FROM attestations WHERE scan_id IN (
            SELECT id FROM scans WHERE product_id = :product_id
        )
    """), {"product_id": product_id})
    db.execute(text("DELETE FROM scans WHERE product_id = :product_id"), {"product_id": product_id})
    db.execute(text("DELETE FROM products WHERE id = :product_id"), {"product_id": product_id})

    db.commit()
