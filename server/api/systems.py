"""
System API endpoints for infrastructure scanning mode.
"""

from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import func
from sqlalchemy.orm import Session

from ..auth import require_write
from ..db import get_db, System, Scan, Package, File
from .schemas import SystemCreate, SystemResponse

router = APIRouter()


@router.get("/", response_model=List[SystemResponse])
def list_systems(
    tag: Optional[str] = None,
    limit: int = Query(default=100, le=1000, description="Maximum results"),
    offset: int = Query(default=0, description="Offset for pagination"),
    db: Session = Depends(get_db),
):
    """List all systems with scan, package, and file counts."""
    scan_counts = (
        db.query(
            Scan.system_id,
            func.count(Scan.id).label("scan_count"),
        )
        .group_by(Scan.system_id)
        .subquery()
    )

    pkg_counts = (
        db.query(
            Package.system_id,
            func.count(Package.id).label("total_packages"),
        )
        .group_by(Package.system_id)
        .subquery()
    )

    file_counts = (
        db.query(
            File.system_id,
            func.count(File.id).label("total_files"),
        )
        .group_by(File.system_id)
        .subquery()
    )

    query = (
        db.query(
            System,
            func.coalesce(scan_counts.c.scan_count, 0).label("scan_count"),
            func.coalesce(pkg_counts.c.total_packages, 0).label("total_packages"),
            func.coalesce(file_counts.c.total_files, 0).label("total_files"),
        )
        .outerjoin(scan_counts, System.id == scan_counts.c.system_id)
        .outerjoin(pkg_counts, System.id == pkg_counts.c.system_id)
        .outerjoin(file_counts, System.id == file_counts.c.system_id)
        .order_by(System.hostname)
    )

    if tag:
        query = query.filter(System.tag == tag)

    query = query.offset(offset).limit(limit)
    results = query.all()

    return [
        SystemResponse(
            id=system.id,
            hostname=system.hostname,
            ip_address=system.ip_address,
            tag=system.tag,
            os_name=system.os_name,
            os_version=system.os_version,
            arch=system.arch,
            last_scan_at=system.last_scan_at,
            created_at=system.created_at,
            scan_count=sc,
            total_packages=pc,
            total_files=fc,
        )
        for system, sc, pc, fc in results
    ]


@router.get("/{hostname}", response_model=SystemResponse)
def get_system(hostname: str, db: Session = Depends(get_db)):
    """Get a specific system by hostname."""
    system = db.query(System).filter(System.hostname == hostname).first()

    if not system:
        raise HTTPException(status_code=404, detail="System not found")

    scan_count = db.query(func.count(Scan.id)).filter(Scan.system_id == system.id).scalar() or 0
    total_packages = db.query(func.count(Package.id)).filter(Package.system_id == system.id).scalar() or 0
    total_files = db.query(func.count(File.id)).filter(File.system_id == system.id).scalar() or 0

    return SystemResponse(
        id=system.id,
        hostname=system.hostname,
        ip_address=system.ip_address,
        tag=system.tag,
        os_name=system.os_name,
        os_version=system.os_version,
        arch=system.arch,
        last_scan_at=system.last_scan_at,
        created_at=system.created_at,
        scan_count=scan_count,
        total_packages=total_packages,
        total_files=total_files,
    )


@router.post("/", response_model=SystemResponse, status_code=201, dependencies=[Depends(require_write)])
def create_system(system: SystemCreate, db: Session = Depends(get_db)):
    """Create a new system."""
    existing = db.query(System).filter(System.hostname == system.hostname).first()
    if existing:
        raise HTTPException(status_code=409, detail="System already exists")

    db_system = System(
        hostname=system.hostname,
        ip_address=system.ip_address,
        tag=system.tag,
        os_name=system.os_name,
        os_version=system.os_version,
        arch=system.arch,
    )
    db.add(db_system)
    db.commit()
    db.refresh(db_system)

    return SystemResponse(
        id=db_system.id,
        hostname=db_system.hostname,
        ip_address=db_system.ip_address,
        tag=db_system.tag,
        os_name=db_system.os_name,
        os_version=db_system.os_version,
        arch=db_system.arch,
        last_scan_at=db_system.last_scan_at,
        created_at=db_system.created_at,
        scan_count=0,
        total_packages=0,
        total_files=0,
    )


@router.put("/{hostname}", response_model=SystemResponse, dependencies=[Depends(require_write)])
def update_system(hostname: str, system: SystemCreate, db: Session = Depends(get_db)):
    """Update a system's metadata."""
    db_system = db.query(System).filter(System.hostname == hostname).first()
    if not db_system:
        raise HTTPException(status_code=404, detail="System not found")

    db_system.ip_address = system.ip_address
    db_system.tag = system.tag
    db_system.os_name = system.os_name
    db_system.os_version = system.os_version
    db_system.arch = system.arch

    db.commit()
    db.refresh(db_system)

    scan_count = db.query(func.count(Scan.id)).filter(Scan.system_id == db_system.id).scalar() or 0
    total_packages = db.query(func.count(Package.id)).filter(Package.system_id == db_system.id).scalar() or 0
    total_files = db.query(func.count(File.id)).filter(File.system_id == db_system.id).scalar() or 0

    return SystemResponse(
        id=db_system.id,
        hostname=db_system.hostname,
        ip_address=db_system.ip_address,
        tag=db_system.tag,
        os_name=db_system.os_name,
        os_version=db_system.os_version,
        arch=db_system.arch,
        last_scan_at=db_system.last_scan_at,
        created_at=db_system.created_at,
        scan_count=scan_count,
        total_packages=total_packages,
        total_files=total_files,
    )


@router.delete("/{hostname}", status_code=204, dependencies=[Depends(require_write)])
def delete_system(hostname: str, db: Session = Depends(get_db)):
    """Delete a system and all its scans."""
    system = db.query(System).filter(System.hostname == hostname).first()
    if not system:
        raise HTTPException(status_code=404, detail="System not found")

    db.delete(system)
    db.commit()


@router.get("/tags/", response_model=List[str])
def list_tags(db: Session = Depends(get_db)):
    """List all unique system tags."""
    tags = db.query(System.tag).filter(System.tag.isnot(None)).distinct().all()
    return [t[0] for t in tags]
