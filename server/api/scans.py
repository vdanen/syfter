"""
Scan API endpoints.
"""

import gc
import gzip
import io
import json
import logging
import threading
import time
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, Form
from sqlalchemy.orm import Session

from ..config import get_config
from ..db import get_db, Product, Scan, Package, File as FileModel, ImageLayer, Attestation, Tag, ScanTag
from ..auth import require_write
from ..storage import get_storage
from .queries import invalidate_stats_cache
from .schemas import (
    ScanResponse,
    ImportResponse,
    ScanMetadata,
    PackageCreate,
    TagCreate,
    TagResponse,
)
from .tags import _apply_tags_to_scan, _get_scan_tag_names, validate_cid_tag_requirement
from ..sbom_formats import convert_sbom, SBOMFormat

logger = logging.getLogger(__name__)
router = APIRouter()

_dep_semaphore = threading.Semaphore(1)

# Maximum decompressed size to prevent zip bombs (4GB)
_MAX_DECOMPRESSED_SIZE = 4 * 1024 * 1024 * 1024  # 4GB for large distros like RHEL


def _safe_gzip_decompress(data: bytes, max_size: int = _MAX_DECOMPRESSED_SIZE) -> bytes:
    """
    Safely decompress gzip data with size limit to prevent decompression bombs.
    """
    decompressor = gzip.GzipFile(fileobj=io.BytesIO(data))
    chunks = []
    total_size = 0

    while True:
        chunk = decompressor.read(1024 * 1024)
        if not chunk:
            break
        total_size += len(chunk)
        if total_size > max_size:
            raise ValueError(
                f"Decompressed data ({total_size // (1024*1024)}MB so far) exceeds maximum size limit of {max_size // (1024*1024*1024)}GB"
            )
        chunks.append(chunk)

    return b''.join(chunks)


def _validate_sbom_json(data: bytes, name: str = "SBOM") -> dict:
    """
    Validate that compressed data is valid gzip JSON.

    Args:
        data: Compressed gzip data
        name: Name for error messages

    Returns:
        Parsed JSON dict

    Raises:
        HTTPException: If data is invalid
    """
    try:
        decompressed = _safe_gzip_decompress(data)
    except gzip.BadGzipFile:
        raise HTTPException(status_code=400, detail=f"Invalid {name}: not valid gzip data")
    except ValueError as e:
        raise HTTPException(status_code=400, detail=f"Invalid {name}: {e}")

    try:
        return json.loads(decompressed.decode("utf-8"))
    except json.JSONDecodeError as e:
        raise HTTPException(status_code=400, detail=f"Invalid {name}: not valid JSON - {e}")
    except UnicodeDecodeError as e:
        raise HTTPException(status_code=400, detail=f"Invalid {name}: not valid UTF-8 - {e}")


def _generate_storage_key(product_name: str, product_version: str, scan_id: int, suffix: str) -> str:
    """Generate a storage key for an SBOM."""
    return f"{product_name}/{product_version}/{scan_id}/{suffix}"


def _insert_dependencies_background(scan_id, product_id, dep_compressed, packages_by_key, db_url):
    """Insert dependencies in a background thread with its own DB connection."""
    from ..db.session import get_session_factory
    SessionLocal = get_session_factory()
    db = SessionLocal()

    is_postgres = "postgresql" in db_url
    raw_conn = None
    dep_count = 0

    try:
        db.execute(
            Scan.__table__.update().where(Scan.id == scan_id).values(deps_status="processing")
        )
        db.commit()

        engine = db.get_bind()
        raw_conn = engine.raw_connection()
        DEP_BATCH = 10000
        cursor = raw_conn.cursor()

        if is_postgres:
            from psycopg2.extras import execute_values
            dep_sql = """INSERT INTO dependencies (package_id, scan_id, product_id, dependency_name, dependency_version, dependency_flags, dependency_type)
                         VALUES %s"""
        else:
            dep_sql = """INSERT INTO dependencies (package_id, scan_id, product_id, dependency_name, dependency_version, dependency_flags, dependency_type)
                         VALUES (?, ?, ?, ?, ?, ?, ?)"""

        _dep_semaphore.acquire()
        try:
            dep_json_bytes = _safe_gzip_decompress(dep_compressed)
            del dep_compressed

            dep_text = dep_json_bytes.decode("utf-8")
            del dep_json_bytes
            gc.collect()

            decoder = json.JSONDecoder()
            pos = 0
            length = len(dep_text)

            while pos < length and dep_text[pos] in ' \t\n\r':
                pos += 1
            if pos < length and dep_text[pos] == '[':
                pos += 1

            batch = []
            while pos < length:
                while pos < length and dep_text[pos] in ' \t\n\r,':
                    pos += 1
                if pos >= length or dep_text[pos] == ']':
                    break

                dep, end_pos = decoder.raw_decode(dep_text, pos)
                pos = end_pos

                pkg_key = (dep.get("package_name", ""), dep.get("package_version"), dep.get("package_arch"))
                package_id = packages_by_key.get(pkg_key)
                batch.append((
                    package_id,
                    scan_id,
                    product_id,
                    dep.get("dependency_name", ""),
                    dep.get("dependency_version"),
                    dep.get("dependency_flags"),
                    dep.get("dependency_type", "requires"),
                ))
                if len(batch) >= DEP_BATCH:
                    if is_postgres:
                        execute_values(cursor, dep_sql, batch, page_size=1000)
                    else:
                        cursor.executemany(dep_sql, batch)
                    raw_conn.commit()
                    dep_count += len(batch)
                    logger.info(f"  [bg] Dependencies batch: {dep_count} inserted so far (scan {scan_id})")
                    batch = []

            if batch:
                if is_postgres:
                    execute_values(cursor, dep_sql, batch, page_size=1000)
                else:
                    cursor.executemany(dep_sql, batch)
                raw_conn.commit()
                dep_count += len(batch)

            del dep_text
            gc.collect()
        finally:
            _dep_semaphore.release()

        db.execute(
            Scan.__table__.update().where(Scan.id == scan_id).values(
                deps_status="complete", deps_count=dep_count
            )
        )
        db.commit()
        logger.info(f"  [bg] Dependencies complete for scan {scan_id}: {dep_count} records")

    except Exception as e:
        logger.exception(f"  [bg] Failed to insert dependencies for scan {scan_id}: {e}")
        try:
            db.execute(
                Scan.__table__.update().where(Scan.id == scan_id).values(deps_status="failed")
            )
            db.commit()
        except Exception:
            pass
    finally:
        if raw_conn is not None:
            try:
                raw_conn.close()
            except Exception:
                pass
        db.close()


@router.get("/", response_model=List[ScanResponse])
def list_scans(
    product_name: Optional[str] = None,
    limit: int = 100,
    offset: int = 0,
    db: Session = Depends(get_db),
):
    """List scans, optionally filtered by product."""
    query = (
        db.query(Scan, Product.name, Product.version)
        .join(Product, Scan.product_id == Product.id)
    )

    if product_name:
        query = query.filter(Product.name == product_name)

    query = query.order_by(Scan.scan_timestamp.desc()).offset(offset).limit(limit)
    results = query.all()

    scan_ids = [scan.id for scan, _, _ in results]
    tag_map = {}
    if scan_ids:
        tag_rows = (
            db.query(ScanTag.scan_id, Tag.name)
            .join(Tag, ScanTag.tag_id == Tag.id)
            .filter(ScanTag.scan_id.in_(scan_ids))
            .all()
        )
        for sid, tname in tag_rows:
            tag_map.setdefault(sid, []).append(tname)

    return [
        ScanResponse(
            id=scan.id,
            product_id=scan.product_id,
            product_name=pname,
            product_version=pversion,
            source_path=scan.source_path,
            source_type=scan.source_type,
            scan_timestamp=scan.scan_timestamp,
            syft_version=scan.syft_version,
            package_count=scan.package_count,
            file_count=scan.file_count,
            original_size_bytes=scan.original_size_bytes,
            modified_size_bytes=scan.modified_size_bytes,
            deps_status=scan.deps_status,
            deps_count=scan.deps_count,
            tags=sorted(tag_map.get(scan.id, [])),
        )
        for scan, pname, pversion in results
    ]


@router.get("/{scan_id}", response_model=ScanResponse)
def get_scan(scan_id: int, db: Session = Depends(get_db)):
    """Get a specific scan."""
    result = (
        db.query(Scan, Product.name, Product.version)
        .join(Product, Scan.product_id == Product.id)
        .filter(Scan.id == scan_id)
        .first()
    )

    if not result:
        raise HTTPException(status_code=404, detail="Scan not found")

    scan, pname, pversion = result
    return ScanResponse(
        id=scan.id,
        product_id=scan.product_id,
        product_name=pname,
        product_version=pversion,
        source_path=scan.source_path,
        source_type=scan.source_type,
        scan_timestamp=scan.scan_timestamp,
        syft_version=scan.syft_version,
        package_count=scan.package_count,
        file_count=scan.file_count,
        original_size_bytes=scan.original_size_bytes,
        modified_size_bytes=scan.modified_size_bytes,
        deps_status=scan.deps_status,
        deps_count=scan.deps_count,
        tags=_get_scan_tag_names(db, scan.id),
    )


@router.post("/upload", response_model=ScanResponse, status_code=201, dependencies=[Depends(require_write)])
async def upload_scan(
    product_name: str = Form(...),
    product_version: str = Form(...),
    source_path: str = Form(...),
    source_type: str = Form("directory"),
    syft_version: Optional[str] = Form(None),
    ps_update_stream: Optional[str] = Form(None),
    ps_module: Optional[str] = Form(None),
    original_sbom: UploadFile = File(..., description="Original syft-json SBOM (gzip compressed)"),
    modified_sbom: UploadFile = File(..., description="Modified syft-json SBOM (gzip compressed)"),
    packages_json: UploadFile = File(..., description="Package index JSON (gzip compressed)"),
    dependencies_json: Optional[UploadFile] = File(None, description="Dependency index JSON (gzip compressed)"),
    image_layers_json: Optional[UploadFile] = File(None, description="Container layer chain JSON (gzip compressed)"),
    attestation_json: Optional[UploadFile] = File(None, description="Cosign attestation data JSON (gzip compressed)"),
    tags: Optional[str] = Form(None, description="Comma-separated tag names to apply to the scan"),
    db: Session = Depends(get_db),
):
    """
    Upload a complete scan with SBOMs and package index.

    All files should be gzip compressed JSON.
    If a scan already exists for this product, it will be replaced.
    """
    validate_cid_tag_requirement(tags)
    start_time = time.time()
    logger.info(f"Starting upload for {product_name}-{product_version}")

    storage = get_storage()

    # Get or create product
    product = (
        db.query(Product)
        .filter(Product.name == product_name, Product.version == product_version)
        .first()
    )
    if not product:
        product = Product(
            name=product_name,
            version=product_version,
            cpe_product=product_name,
            ps_update_stream=ps_update_stream,
            ps_module=ps_module,
        )
        db.add(product)
        db.commit()
        db.refresh(product)
    else:
        if ps_update_stream and product.ps_update_stream != ps_update_stream:
            product.ps_update_stream = ps_update_stream
        if ps_module and product.ps_module != ps_module:
            product.ps_module = ps_module
        if db.is_modified(product):
            db.commit()
    logger.info(f"Product resolved: id={product.id}")

    # Delete existing scan for this product (replace behavior)
    existing_scan = (
        db.query(Scan)
        .filter(Scan.product_id == product.id)
        .first()
    )
    if existing_scan:
        logger.info(f"Deleting existing scan {existing_scan.id}")
        delete_start = time.time()

        # Delete old SBOM and attestation files from storage
        try:
            storage.delete(existing_scan.original_sbom_key)
            storage.delete(existing_scan.modified_sbom_key)
        except Exception:
            pass
        for att in db.query(Attestation).filter(Attestation.scan_id == existing_scan.id).all():
            try:
                storage.delete(att.attestation_key)
            except Exception:
                pass

        # Use raw SQL for fast deletion (ORM is extremely slow for millions of rows)
        connection = db.connection()
        raw_conn = connection.connection.dbapi_connection
        cursor = raw_conn.cursor()

        # Check if PostgreSQL or SQLite
        is_postgres = 'psycopg' in type(raw_conn).__module__ or 'postgresql' in str(db.bind.url)
        param = '%s' if is_postgres else '?'

        # Delete in FK order: dependencies -> files -> packages -> layers/attestations -> scan
        logger.info("Deleting dependencies...")
        cursor.execute(f"DELETE FROM dependencies WHERE scan_id = {param}", (existing_scan.id,))
        raw_conn.commit()

        logger.info("Deleting files...")
        cursor.execute(f"DELETE FROM files WHERE scan_id = {param}", (existing_scan.id,))
        raw_conn.commit()
        files_time = time.time() - delete_start
        logger.info(f"Files deleted in {files_time:.1f}s")

        logger.info("Deleting packages...")
        pkg_start = time.time()
        cursor.execute(f"DELETE FROM packages WHERE scan_id = {param}", (existing_scan.id,))
        raw_conn.commit()
        logger.info(f"Packages deleted in {time.time() - pkg_start:.1f}s")

        cursor.execute(f"DELETE FROM scan_tags WHERE scan_id = {param}", (existing_scan.id,))
        cursor.execute(f"DELETE FROM image_layers WHERE scan_id = {param}", (existing_scan.id,))
        cursor.execute(f"DELETE FROM attestations WHERE scan_id = {param}", (existing_scan.id,))
        raw_conn.commit()

        logger.info("Deleting scan record...")
        cursor.execute(f"DELETE FROM scans WHERE id = {param}", (existing_scan.id,))
        raw_conn.commit()

        # Refresh ORM session
        db.expire_all()

        logger.info(f"Existing scan deleted in {time.time() - delete_start:.1f}s")

    # Read uploaded files
    logger.info("Reading uploaded files...")
    original_data = await original_sbom.read()
    modified_data = await modified_sbom.read()
    packages_data = await packages_json.read()
    logger.info(f"Files read: original={len(original_data)/1024/1024:.1f}MB, modified={len(modified_data)/1024/1024:.1f}MB, packages={len(packages_data)/1024:.1f}KB")

    # Validate SBOM files are proper gzip (check magic bytes, don't decompress)
    # Decompressing a truncated slice fails with EOFError for large SBOMs,
    # so we just verify the gzip magic bytes are present.
    logger.info("Validating SBOM files...")
    for label, sbom_data in [("original", original_data), ("modified", modified_data)]:
        if len(sbom_data) < 2 or sbom_data[:2] != b"\x1f\x8b":
            raise HTTPException(
                status_code=400,
                detail=f"Invalid {label} SBOM: not valid gzip data (missing magic bytes)",
            )

    # Parse packages for indexing - use streaming with size limit
    logger.info("Parsing packages JSON...")
    try:
        # Decompress with size limit
        packages_json_bytes = _safe_gzip_decompress(packages_data)
        # Free the compressed data immediately
        del packages_data

        # Parse JSON
        packages_list = json.loads(packages_json_bytes.decode("utf-8"))
        # Free the JSON bytes immediately
        del packages_json_bytes

        gc.collect()
        logger.info(f"JSON parsed, memory cleaned up")
    except MemoryError:
        logger.error("Out of memory parsing packages JSON")
        raise HTTPException(status_code=507, detail="Server out of memory processing this upload. Try again or contact admin.")
    except ValueError as e:
        raise HTTPException(status_code=400, detail=f"Packages JSON too large: {e}")
    except json.JSONDecodeError as e:
        raise HTTPException(status_code=400, detail=f"Invalid packages JSON format: {e}")
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Invalid packages JSON: {e}")

    total_files = sum(len(p.get("files", [])) for p in packages_list)
    logger.info(f"Parsed {len(packages_list)} packages with {total_files} files")

    # Read raw dependency data (defer parsing until insert time to reduce peak memory)
    _dep_compressed = None
    if dependencies_json is not None:
        logger.info("Reading dependencies JSON...")
        try:
            _dep_compressed = await dependencies_json.read()
            logger.info(f"Dependencies data read: {len(_dep_compressed)/1024:.0f}KB compressed")
        except Exception as e:
            logger.warning(f"Failed to read dependencies JSON, skipping: {e}")
            _dep_compressed = None

    # Create scan record first to get ID
    scan = Scan(
        product_id=product.id,
        source_path=source_path,
        source_type=source_type,
        syft_version=syft_version,
        original_sbom_key="",  # Will update after
        modified_sbom_key="",
        package_count=len(packages_list),
        file_count=total_files,
        original_size_bytes=len(original_data),
        modified_size_bytes=len(modified_data),
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)
    logger.info(f"Scan record created: id={scan.id}")

    # Generate storage keys and store SBOMs
    logger.info("Storing SBOMs to object storage...")
    original_key = _generate_storage_key(product_name, product_version, scan.id, "original.json.gz")
    modified_key = _generate_storage_key(product_name, product_version, scan.id, "modified.json.gz")

    storage.put(original_key, original_data)
    storage.put(modified_key, modified_data)
    del original_data, modified_data
    logger.info("SBOMs stored and freed from memory")

    # Update scan with storage keys
    scan.original_sbom_key = original_key
    scan.modified_sbom_key = modified_key

    # Index packages and files using raw SQL for maximum performance
    logger.info("Indexing packages and files...")

    # Use raw connection for fast bulk inserts
    connection = db.connection()
    raw_conn = connection.connection.dbapi_connection

    # Check if PostgreSQL or SQLite by looking at the connection type
    is_postgres = 'psycopg' in type(raw_conn).__module__ or 'postgresql' in str(db.bind.url)

    # Insert packages and get their IDs
    packages_count = len(packages_list)
    logger.info(f"Inserting {packages_count} packages...")
    bulk_start = time.time()

    # Build package tuples
    package_tuples = [
        (
            scan.id,
            product.id,
            pkg.get("name", ""),
            pkg.get("version"),
            pkg.get("release"),
            pkg.get("arch"),
            pkg.get("epoch"),
            pkg.get("source_rpm"),
            pkg.get("license"),
            pkg.get("purl"),
            pkg.get("cpes"),
            pkg.get("layer_id"),
            pkg.get("layer_index"),
            pkg.get("source_image"),
        )
        for pkg in packages_list
    ]

    _pkg_cols = "scan_id, product_id, name, version, release, arch, epoch, source_rpm, license, purl, cpes, layer_id, layer_index, source_image"

    if is_postgres:
        from psycopg2.extras import execute_values
        cursor = raw_conn.cursor()
        execute_values(
            cursor,
            f"INSERT INTO packages ({_pkg_cols}) VALUES %s",
            package_tuples,
            page_size=1000
        )
        raw_conn.commit()
    else:
        cursor = raw_conn.cursor()
        cursor.executemany(
            f"INSERT INTO packages ({_pkg_cols}) VALUES ({','.join('?' * 14)})",
            package_tuples
        )
        raw_conn.commit()

    logger.info(f"Packages inserted in {time.time() - bulk_start:.1f}s")

    # Check if we should skip file indexing for large scans
    config = get_config()
    skip_threshold = config.skip_file_index_threshold
    skip_files = skip_threshold > 0 and total_files > skip_threshold

    if skip_files:
        logger.info(f"Skipping file indexing: {total_files} files exceeds threshold of {skip_threshold}")
        logger.info("File search will not be available for this scan, but packages are indexed")

    # Retrieve package IDs (needed for file and/or dependency insertion)
    need_pkg_ids = (not skip_files and total_files > 0) or _dep_compressed
    packages_by_key = {}
    if need_pkg_ids:
        logger.info("Retrieving package IDs...")
        cursor = raw_conn.cursor()
        cursor.execute("SELECT id, name, version, arch FROM packages WHERE scan_id = %s" if is_postgres else
                       "SELECT id, name, version, arch FROM packages WHERE scan_id = ?", (scan.id,))
        packages_by_key = {(row[1], row[2], row[3]): row[0] for row in cursor.fetchall()}

    file_count_actual = 0
    if not skip_files and total_files > 0:
        logger.info(f"Inserting {total_files} files...")
        bulk_start = time.time()

        if is_postgres:
            # Stream files directly to a temp file, then COPY - avoids holding all in memory
            import tempfile
            import os

            logger.info("Writing files to temp file for COPY...")
            with tempfile.NamedTemporaryFile(mode='w', suffix='.tsv', delete=False) as tmp:
                tmp_path = tmp.name
                for pkg in packages_list:
                    key = (pkg.get("name", ""), pkg.get("version"), pkg.get("arch"))
                    package_id = packages_by_key.get(key)
                    if package_id:
                        for f in pkg.get("files", []):
                            # Format for COPY: tab-separated, \N for NULL
                            path = f.get("path", "")
                            digest = f.get("digest")
                            algo = f.get("digest_algorithm", "sha256")

                            # Escape special chars
                            path = path.replace('\\', '\\\\').replace('\t', '\\t').replace('\n', '\\n') if path else ''
                            digest_str = digest.replace('\\', '\\\\') if digest else '\\N'
                            algo_str = algo.replace('\\', '\\\\') if algo else '\\N'

                            tmp.write(f"{package_id}\t{scan.id}\t{product.id}\t{path}\t{digest_str}\t{algo_str}\n")
                            file_count_actual += 1

                            # Log progress periodically
                            if file_count_actual % 1000000 == 0:
                                logger.info(f"Files written to temp: {file_count_actual}/{total_files}")

            logger.info(f"Temp file written: {file_count_actual} files, {os.path.getsize(tmp_path)/1024/1024:.1f}MB")

            # Free packages_list memory before COPY
            if not _dep_compressed:
                del packages_list
                gc.collect()
                logger.info("Memory freed, starting COPY...")

            # COPY from file
            cursor = raw_conn.cursor()
            with open(tmp_path, 'r') as f:
                cursor.copy_from(
                    f,
                    'files',
                    columns=('package_id', 'scan_id', 'product_id', 'path', 'digest', 'digest_algorithm'),
                    null='\\N'
                )
            raw_conn.commit()

            # Clean up temp file
            os.unlink(tmp_path)
            logger.info(f"COPY complete")
        else:
            # SQLite - stream directly without building full list
            cursor = raw_conn.cursor()
            batch = []
            batch_size = 50000

            for pkg in packages_list:
                key = (pkg.get("name", ""), pkg.get("version"), pkg.get("arch"))
                package_id = packages_by_key.get(key)
                if package_id:
                    for f in pkg.get("files", []):
                        batch.append((
                            package_id,
                            scan.id,
                            product.id,
                            f.get("path", ""),
                            f.get("digest"),
                            f.get("digest_algorithm", "sha256"),
                        ))
                        file_count_actual += 1

                        if len(batch) >= batch_size:
                            cursor.executemany(
                                """INSERT INTO files (package_id, scan_id, product_id, path, digest, digest_algorithm)
                                   VALUES (?, ?, ?, ?, ?, ?)""",
                                batch
                            )
                            batch = []
                            if file_count_actual % 500000 == 0:
                                raw_conn.commit()
                                logger.info(f"Files progress: {file_count_actual}/{total_files}")

            # Insert remaining
            if batch:
                cursor.executemany(
                    """INSERT INTO files (package_id, scan_id, product_id, path, digest, digest_algorithm)
                       VALUES (?, ?, ?, ?, ?, ?)""",
                    batch
                )
            raw_conn.commit()

        logger.info(f"Files inserted in {time.time() - bulk_start:.1f}s")

    # Insert dependencies in a background thread to avoid blocking the worker
    dep_count = 0
    if _dep_compressed:
        scan.deps_status = "pending"
        db.commit()

        t = threading.Thread(
            target=_insert_dependencies_background,
            args=(scan.id, product.id, _dep_compressed, packages_by_key, str(db.bind.url)),
            daemon=True,
            name=f"deps-{scan.id}",
        )
        t.start()
        logger.info(f"Background dependency insertion started for scan {scan.id}")

    # Process image layers (container scans)
    if image_layers_json is not None:
        try:
            layers_data = await image_layers_json.read()
            layers_list = json.loads(_safe_gzip_decompress(layers_data).decode("utf-8"))
            scan.image_layers_json = json.dumps(layers_list)

            layer_tuples = [
                (scan.id, layer.get("layer_id", ""), layer.get("layer_index", i),
                 layer.get("source_image"), bool(layer.get("is_base", False)))
                for i, layer in enumerate(layers_list)
            ]
            cursor = raw_conn.cursor()
            if is_postgres:
                from psycopg2.extras import execute_values
                execute_values(
                    cursor,
                    "INSERT INTO image_layers (scan_id, layer_id, layer_index, source_image, is_base) VALUES %s",
                    layer_tuples,
                )
            else:
                cursor.executemany(
                    "INSERT INTO image_layers (scan_id, layer_id, layer_index, source_image, is_base) VALUES (?, ?, ?, ?, ?)",
                    layer_tuples,
                )
            raw_conn.commit()
            logger.info(f"Stored {len(layers_list)} image layers")
        except Exception as e:
            logger.warning(f"Failed to process image layers: {e}")

    # Process attestations (container scans)
    if attestation_json is not None:
        import base64
        from datetime import datetime as dt
        try:
            att_data = await attestation_json.read()
            att_list = json.loads(_safe_gzip_decompress(att_data).decode("utf-8"))

            att_key = _generate_storage_key(product_name, product_version, scan.id, "attestation.json.gz")
            storage.put(att_key, gzip.compress(json.dumps(att_list).encode()))

            for envelope in att_list:
                predicate_type = None
                builder_id = None
                build_type = None
                build_started = None
                build_finished = None

                payload_b64 = envelope.get("payload", "")
                if payload_b64:
                    try:
                        statement = json.loads(base64.b64decode(payload_b64))
                        predicate_type = statement.get("predicateType")
                        predicate = statement.get("predicate", {})
                        builder_id = predicate.get("builder", {}).get("id")
                        build_type = predicate.get("buildType")
                        meta = predicate.get("metadata", {})
                        if meta.get("buildStartedOn"):
                            build_started = dt.fromisoformat(meta["buildStartedOn"].replace("Z", "+00:00"))
                        if meta.get("buildFinishedOn"):
                            build_finished = dt.fromisoformat(meta["buildFinishedOn"].replace("Z", "+00:00"))
                    except Exception:
                        predicate_type = envelope.get("_layer_annotations", {}).get("predicateType")

                att_record = Attestation(
                    scan_id=scan.id,
                    predicate_type=predicate_type,
                    builder_id=builder_id,
                    build_type=build_type,
                    build_started_on=build_started,
                    build_finished_on=build_finished,
                    attestation_key=att_key,
                )
                db.add(att_record)

            db.commit()
            logger.info(f"Stored {len(att_list)} attestation records")
        except Exception as e:
            logger.warning(f"Failed to process attestations: {e}")

    # Refresh session to pick up raw SQL changes
    db.expire_all()

    elapsed = time.time() - start_time
    logger.info(f"Upload complete: {packages_count} packages, {file_count_actual} files, {dep_count} deps indexed in {elapsed:.1f}s")

    invalidate_stats_cache()

    # Apply tags if provided
    tag_names = []
    if tags:
        tag_names = _apply_tags_to_scan(db, scan.id, [t.strip() for t in tags.split(",")])
        db.commit()

    return ScanResponse(
        id=scan.id,
        product_id=scan.product_id,
        product_name=product.name,
        product_version=product.version,
        source_path=scan.source_path,
        source_type=scan.source_type,
        scan_timestamp=scan.scan_timestamp,
        syft_version=scan.syft_version,
        package_count=scan.package_count,
        file_count=scan.file_count,
        original_size_bytes=scan.original_size_bytes,
        modified_size_bytes=scan.modified_size_bytes,
        deps_status=scan.deps_status,
        deps_count=scan.deps_count,
        tags=tag_names,
    )


@router.post("/import", response_model=ImportResponse, status_code=201, dependencies=[Depends(require_write)])
async def import_sbom(
    product_name: str = Form(...),
    product_version: str = Form(...),
    source_type: str = Form("sbom"),
    description: Optional[str] = Form(None),
    tags: Optional[str] = Form(None, description="Comma-separated tag names to apply to the scan"),
    sbom: UploadFile = File(..., description="SBOM file (SPDX, CycloneDX, or syft-json; gzip or plain JSON)"),
    db: Session = Depends(get_db),
):
    """
    Import an SBOM in any supported format.

    Auto-detects SPDX 2.x, CycloneDX 1.x, or syft-json format. Stores the
    original SBOM in object storage and indexes all packages in the database.
    Accepts both gzip-compressed and plain JSON uploads.
    """
    validate_cid_tag_requirement(tags)
    start_time = time.time()
    logger.info(f"Starting SBOM import for {product_name}-{product_version}")

    raw_data = await sbom.read()
    if not raw_data:
        raise HTTPException(status_code=400, detail="Empty SBOM file")

    is_gzip = len(raw_data) >= 2 and raw_data[:2] == b"\x1f\x8b"
    if is_gzip:
        try:
            json_bytes = _safe_gzip_decompress(raw_data)
        except Exception as e:
            raise HTTPException(status_code=400, detail=f"Failed to decompress gzip: {e}")
    else:
        json_bytes = raw_data

    try:
        sbom_dict = json.loads(json_bytes.decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError) as e:
        raise HTTPException(status_code=400, detail=f"Invalid JSON: {e}")

    del json_bytes
    gc.collect()

    try:
        detected_format, packages_list, deps_list = convert_sbom(sbom_dict)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    if not packages_list:
        raise HTTPException(status_code=400, detail=f"SBOM ({detected_format.value}) contained no packages")

    logger.info(f"Detected {detected_format.value} format, {len(packages_list)} packages extracted")

    storage = get_storage()

    product = (
        db.query(Product)
        .filter(Product.name == product_name, Product.version == product_version)
        .first()
    )
    if not product:
        product = Product(
            name=product_name,
            version=product_version,
            cpe_product=product_name,
        )
        db.add(product)
        db.commit()
        db.refresh(product)
    logger.info(f"Product resolved: id={product.id}")

    existing_scan = db.query(Scan).filter(Scan.product_id == product.id).first()
    if existing_scan:
        logger.info(f"Deleting existing scan {existing_scan.id}")
        try:
            storage.delete(existing_scan.original_sbom_key)
            storage.delete(existing_scan.modified_sbom_key)
        except Exception:
            pass
        connection = db.connection()
        raw_conn = connection.connection.dbapi_connection
        is_postgres = 'psycopg' in type(raw_conn).__module__ or 'postgresql' in str(db.bind.url)
        param = '%s' if is_postgres else '?'
        cursor = raw_conn.cursor()
        for table in ["dependencies", "files", "packages", "scan_tags", "image_layers", "attestations", "scans"]:
            col = "id" if table == "scans" else "scan_id"
            cursor.execute(f"DELETE FROM {table} WHERE {col} = {param}", (existing_scan.id,))
            raw_conn.commit()
        db.expire_all()

    # Store original SBOM (compress if not already gzip)
    sbom_gz = raw_data if is_gzip else gzip.compress(raw_data)
    del raw_data

    scan = Scan(
        product_id=product.id,
        source_path=description or f"{detected_format.value} import",
        source_type=source_type,
        syft_version=f"import-{detected_format.value}",
        original_sbom_key="",
        modified_sbom_key="",
        package_count=len(packages_list),
        file_count=0,
        original_size_bytes=len(sbom_gz),
        modified_size_bytes=0,
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)

    original_key = _generate_storage_key(product_name, product_version, scan.id, "original.json.gz")
    storage.put(original_key, sbom_gz)
    del sbom_gz

    scan.original_sbom_key = original_key
    scan.modified_sbom_key = original_key

    # Normalize CPE lists to JSON strings for DB storage
    for pkg in packages_list:
        cpes = pkg.get("cpes")
        if isinstance(cpes, list):
            pkg["cpes"] = json.dumps(cpes)

    # Bulk insert packages
    connection = db.connection()
    raw_conn = connection.connection.dbapi_connection
    is_postgres = 'psycopg' in type(raw_conn).__module__ or 'postgresql' in str(db.bind.url)

    scan.package_count = len(packages_list)

    package_tuples = [
        (
            scan.id, product.id,
            pkg.get("name", ""), pkg.get("version"), pkg.get("release"),
            pkg.get("arch"), pkg.get("epoch"), pkg.get("source_rpm"),
            pkg.get("license"), pkg.get("purl"), pkg.get("cpes"),
            pkg.get("layer_id"), pkg.get("layer_index"), pkg.get("source_image"),
        )
        for pkg in packages_list
    ]
    del packages_list

    _pkg_cols = "scan_id, product_id, name, version, release, arch, epoch, source_rpm, license, purl, cpes, layer_id, layer_index, source_image"

    cursor = raw_conn.cursor()
    if is_postgres:
        from psycopg2.extras import execute_values
        execute_values(cursor, f"INSERT INTO packages ({_pkg_cols}) VALUES %s", package_tuples, page_size=1000)
    else:
        cursor.executemany(f"INSERT INTO packages ({_pkg_cols}) VALUES ({','.join('?' * 14)})", package_tuples)
    raw_conn.commit()
    del package_tuples

    db.expire_all()
    db.commit()

    if deps_list:
        cursor = raw_conn.cursor()
        cursor.execute(
            ("SELECT id, name, version, arch FROM packages WHERE scan_id = %s" if is_postgres
             else "SELECT id, name, version, arch FROM packages WHERE scan_id = ?"),
            (scan.id,),
        )
        packages_by_key = {(row[1], row[2], row[3]): row[0] for row in cursor.fetchall()}
        dep_compressed = gzip.compress(json.dumps(deps_list).encode())
        scan.deps_status = "pending"
        db.commit()
        t = threading.Thread(
            target=_insert_dependencies_background,
            args=(scan.id, product.id, dep_compressed, packages_by_key, str(db.bind.url)),
            daemon=True,
            name=f"deps-import-{scan.id}",
        )
        t.start()
        logger.info(f"Started background dependency insertion: {len(deps_list)} edges")

    elapsed = time.time() - start_time
    logger.info(f"Import complete: {scan.package_count} packages indexed in {elapsed:.1f}s")

    invalidate_stats_cache()

    tag_names = []
    if tags:
        tag_names = _apply_tags_to_scan(db, scan.id, [t.strip() for t in tags.split(",")])
        db.commit()

    return ImportResponse(
        id=scan.id,
        product_id=scan.product_id,
        product_name=product.name,
        product_version=product.version,
        source_path=scan.source_path,
        source_type=scan.source_type,
        scan_timestamp=scan.scan_timestamp,
        syft_version=scan.syft_version,
        package_count=scan.package_count,
        file_count=0,
        original_size_bytes=scan.original_size_bytes,
        modified_size_bytes=0,
        sbom_format=detected_format.value,
        tags=tag_names,
    )


@router.post("/import-packages", response_model=ScanResponse, status_code=201, dependencies=[Depends(require_write)])
async def import_packages(
    product_name: str = Form(..., description="Product or project identifier"),
    product_version: str = Form("latest", description="Version label (default: latest)"),
    source_type: str = Form("package-list"),
    packages: UploadFile = File(..., description="Package list (JSON array or CSV, plain or gzip)"),
    tags: Optional[str] = Form(None, description="Comma-separated tag names to apply to the scan"),
    db: Session = Depends(get_db),
):
    """
    Import a plain package list (JSON array or CSV) without a full SBOM.

    Accepts either a JSON array of objects with at minimum a 'name' field,
    or a CSV file with a header row. Auto-detects format.
    """
    validate_cid_tag_requirement(tags)
    import csv as csv_mod

    start_time = time.time()
    logger.info(f"Starting package-list import for {product_name}-{product_version}")

    raw_data = await packages.read()
    if not raw_data:
        raise HTTPException(status_code=400, detail="Empty package file")

    is_gzip = len(raw_data) >= 2 and raw_data[:2] == b"\x1f\x8b"
    if is_gzip:
        try:
            text_data = _safe_gzip_decompress(raw_data).decode("utf-8")
        except Exception as e:
            raise HTTPException(status_code=400, detail=f"Failed to decompress: {e}")
    else:
        try:
            text_data = raw_data.decode("utf-8")
        except UnicodeDecodeError as e:
            raise HTTPException(status_code=400, detail=f"Invalid UTF-8: {e}")

    # Auto-detect JSON vs CSV
    stripped = text_data.lstrip()
    packages_list = []

    if stripped.startswith("[") or stripped.startswith("{"):
        try:
            parsed = json.loads(text_data)
        except json.JSONDecodeError as e:
            raise HTTPException(status_code=400, detail=f"Invalid JSON: {e}")

        if isinstance(parsed, list):
            packages_list = parsed
        elif isinstance(parsed, dict):
            packages_list = [parsed]
        else:
            raise HTTPException(status_code=400, detail="JSON must be an array of package objects")
    else:
        reader = csv_mod.DictReader(io.StringIO(text_data))
        for row in reader:
            pkg = {k.strip(): v.strip() if v else None for k, v in row.items() if k}
            if pkg.get("name"):
                packages_list.append(pkg)

    if not packages_list:
        raise HTTPException(status_code=400, detail="No packages found in file")

    for i, pkg in enumerate(packages_list):
        if not pkg.get("name"):
            raise HTTPException(status_code=400, detail=f"Package at index {i} missing required 'name' field")

    logger.info(f"Parsed {len(packages_list)} packages")

    storage = get_storage()

    # Get or create product
    product = (
        db.query(Product)
        .filter(Product.name == product_name, Product.version == product_version)
        .first()
    )
    if not product:
        product = Product(
            name=product_name,
            version=product_version,
            cpe_product=product_name,
        )
        db.add(product)
        db.commit()
        db.refresh(product)
    logger.info(f"Product resolved: id={product.id}")

    # Delete existing scan (replace behavior)
    existing_scan = db.query(Scan).filter(Scan.product_id == product.id).first()
    if existing_scan:
        logger.info(f"Deleting existing scan {existing_scan.id}")
        try:
            storage.delete(existing_scan.original_sbom_key)
            storage.delete(existing_scan.modified_sbom_key)
        except Exception:
            pass

        connection = db.connection()
        raw_conn = connection.connection.dbapi_connection
        cursor = raw_conn.cursor()
        is_postgres = 'psycopg' in type(raw_conn).__module__ or 'postgresql' in str(db.bind.url)
        param = '%s' if is_postgres else '?'

        cursor.execute(f"DELETE FROM dependencies WHERE scan_id = {param}", (existing_scan.id,))
        cursor.execute(f"DELETE FROM files WHERE scan_id = {param}", (existing_scan.id,))
        cursor.execute(f"DELETE FROM packages WHERE scan_id = {param}", (existing_scan.id,))
        cursor.execute(f"DELETE FROM scan_tags WHERE scan_id = {param}", (existing_scan.id,))
        cursor.execute(f"DELETE FROM image_layers WHERE scan_id = {param}", (existing_scan.id,))
        cursor.execute(f"DELETE FROM scans WHERE id = {param}", (existing_scan.id,))
        raw_conn.commit()
        db.expire_all()
        logger.info("Existing scan deleted")

    # Store raw upload as the "original" for archival
    archive_data = gzip.compress(raw_data)
    del raw_data

    scan = Scan(
        product_id=product.id,
        source_path="package-list-upload",
        source_type=source_type,
        original_sbom_key="",
        modified_sbom_key="",
        package_count=len(packages_list),
        file_count=0,
        original_size_bytes=len(archive_data),
        modified_size_bytes=0,
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)

    original_key = _generate_storage_key(product_name, product_version, scan.id, "packages.json.gz")
    storage.put(original_key, archive_data)
    del archive_data

    scan.original_sbom_key = original_key
    scan.modified_sbom_key = original_key

    # Bulk insert packages
    package_tuples = [
        (
            scan.id,
            product.id,
            pkg.get("name", ""),
            pkg.get("version"),
            pkg.get("release"),
            pkg.get("arch"),
            pkg.get("epoch"),
            pkg.get("source_rpm"),
            pkg.get("license"),
            pkg.get("purl"),
            pkg.get("cpes"),
            pkg.get("layer_id"),
            pkg.get("layer_index"),
            pkg.get("source_image"),
        )
        for pkg in packages_list
    ]

    _pkg_cols = "scan_id, product_id, name, version, release, arch, epoch, source_rpm, license, purl, cpes, layer_id, layer_index, source_image"

    connection = db.connection()
    raw_conn = connection.connection.dbapi_connection
    is_postgres = 'psycopg' in type(raw_conn).__module__ or 'postgresql' in str(db.bind.url)

    if is_postgres:
        from psycopg2.extras import execute_values
        cursor = raw_conn.cursor()
        execute_values(
            cursor,
            f"INSERT INTO packages ({_pkg_cols}) VALUES %s",
            package_tuples,
            page_size=1000,
        )
        raw_conn.commit()
    else:
        cursor = raw_conn.cursor()
        cursor.executemany(
            f"INSERT INTO packages ({_pkg_cols}) VALUES ({','.join('?' * 14)})",
            package_tuples,
        )
        raw_conn.commit()

    db.commit()
    db.refresh(scan)
    invalidate_stats_cache()

    tag_names = []
    if tags:
        tag_names = _apply_tags_to_scan(db, scan.id, [t.strip() for t in tags.split(",")])
        db.commit()

    elapsed = time.time() - start_time
    logger.info(f"Package-list import complete: {len(packages_list)} packages in {elapsed:.1f}s")

    return ScanResponse(
        id=scan.id,
        product_id=scan.product_id,
        product_name=product.name,
        product_version=product.version,
        source_path=scan.source_path,
        source_type=scan.source_type,
        scan_timestamp=scan.scan_timestamp,
        syft_version=scan.syft_version,
        package_count=scan.package_count,
        file_count=0,
        original_size_bytes=scan.original_size_bytes,
        modified_size_bytes=0,
        tags=tag_names,
    )


@router.delete("/{scan_id}", status_code=204, dependencies=[Depends(require_write)])
def delete_scan(scan_id: int, db: Session = Depends(get_db)):
    """Delete a scan and its associated data."""
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    # Delete SBOM files from storage
    storage = get_storage()
    try:
        storage.delete(scan.original_sbom_key)
        storage.delete(scan.modified_sbom_key)
    except Exception:
        pass
    # Delete attestation S3 objects
    for att in db.query(Attestation).filter(Attestation.scan_id == scan_id).all():
        try:
            storage.delete(att.attestation_key)
        except Exception:
            pass

    # Use raw SQL for fast deletion
    connection = db.connection()
    raw_conn = connection.connection.dbapi_connection
    cursor = raw_conn.cursor()

    is_postgres = 'psycopg' in type(raw_conn).__module__ or 'postgresql' in str(db.bind.url)
    param = '%s' if is_postgres else '?'

    cursor.execute(f"DELETE FROM dependencies WHERE scan_id = {param}", (scan_id,))
    cursor.execute(f"DELETE FROM files WHERE scan_id = {param}", (scan_id,))
    cursor.execute(f"DELETE FROM packages WHERE scan_id = {param}", (scan_id,))
    cursor.execute(f"DELETE FROM scan_tags WHERE scan_id = {param}", (scan_id,))
    cursor.execute(f"DELETE FROM image_layers WHERE scan_id = {param}", (scan_id,))
    cursor.execute(f"DELETE FROM attestations WHERE scan_id = {param}", (scan_id,))
    cursor.execute(f"DELETE FROM scans WHERE id = {param}", (scan_id,))
    raw_conn.commit()
    db.expire_all()

    invalidate_stats_cache()


@router.get("/{scan_id}/tags", response_model=List[TagResponse])
def list_scan_tags(scan_id: int, db: Session = Depends(get_db)):
    """List tags on a scan."""
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    from sqlalchemy import func
    results = (
        db.query(Tag, func.count(ScanTag.id).label("scan_count"))
        .join(ScanTag, ScanTag.tag_id == Tag.id)
        .filter(ScanTag.scan_id == scan_id)
        .group_by(Tag.id)
        .order_by(Tag.name)
        .all()
    )
    return [
        TagResponse(id=tag.id, name=tag.name, created_at=tag.created_at, scan_count=sc)
        for tag, sc in results
    ]


@router.post("/{scan_id}/tags", response_model=List[TagResponse], dependencies=[Depends(require_write)])
def add_scan_tags(scan_id: int, body: TagCreate, db: Session = Depends(get_db)):
    """Add tags to a scan, auto-creating tags that don't exist."""
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    _apply_tags_to_scan(db, scan_id, body.tags)
    db.commit()

    return list_scan_tags(scan_id, db)


@router.delete("/{scan_id}/tags/{tag_name}", status_code=204, dependencies=[Depends(require_write)])
def remove_scan_tag(scan_id: int, tag_name: str, db: Session = Depends(get_db)):
    """Remove a tag from a scan. Does not delete the tag itself."""
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    tag = db.query(Tag).filter(Tag.name == tag_name).first()
    if not tag:
        raise HTTPException(status_code=404, detail="Tag not found")

    scan_tag = (
        db.query(ScanTag)
        .filter(ScanTag.scan_id == scan_id, ScanTag.tag_id == tag.id)
        .first()
    )
    if not scan_tag:
        raise HTTPException(status_code=404, detail="Tag not on this scan")

    db.delete(scan_tag)
    db.commit()
