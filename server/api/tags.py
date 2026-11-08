"""
Tag API endpoints.
"""

import logging
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import func
from sqlalchemy.orm import Session

from ..auth import require_write
from ..config import get_config
from ..db import get_db, Tag, ScanTag, Scan
from .schemas import TagCreate, TagResponse, TagUpdate

logger = logging.getLogger(__name__)

router = APIRouter()

CID_TAG_PREFIX = "CID-"


def validate_cid_tag_requirement(tags: Optional[str]) -> None:
    """Reject uploads missing a CID- prefixed tag when enforcement is enabled."""
    if not get_config().require_cid_tag:
        return
    tag_names = [t.strip() for t in (tags or "").split(",") if t.strip()]
    if not any(name.startswith(CID_TAG_PREFIX) for name in tag_names):
        raise HTTPException(
            status_code=400,
            detail=f"At least one tag with a '{CID_TAG_PREFIX}' prefix is required (e.g. CID-001)",
        )


def _get_or_create_tags(db: Session, tag_names: list[str]) -> list[Tag]:
    """Get or create tags by name. Returns list of Tag objects."""
    tags = []
    for name in tag_names:
        name = name.strip()
        if not name:
            continue
        tag = db.query(Tag).filter(Tag.name == name).first()
        if not tag:
            tag = Tag(name=name)
            db.add(tag)
            db.flush()
        tags.append(tag)
    return tags


def _apply_tags_to_scan(db: Session, scan_id: int, tag_names: list[str]) -> list[str]:
    """Add tags to a scan, auto-creating as needed. Returns final tag list."""
    tags = _get_or_create_tags(db, tag_names)
    for tag in tags:
        existing = (
            db.query(ScanTag)
            .filter(ScanTag.scan_id == scan_id, ScanTag.tag_id == tag.id)
            .first()
        )
        if not existing:
            db.add(ScanTag(scan_id=scan_id, tag_id=tag.id))
    db.flush()
    return _get_scan_tag_names(db, scan_id)


def _get_scan_tag_names(db: Session, scan_id: int) -> list[str]:
    """Get tag names for a scan."""
    rows = (
        db.query(Tag.name)
        .join(ScanTag, ScanTag.tag_id == Tag.id)
        .filter(ScanTag.scan_id == scan_id)
        .order_by(Tag.name)
        .all()
    )
    return [r[0] for r in rows]


@router.get("/", response_model=List[TagResponse])
def list_tags(
    name: Optional[str] = Query(default=None, description="Filter by tag name (% wildcard)"),
    limit: int = Query(default=100, ge=0, le=1000),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
):
    """List all tags with scan counts."""
    query = (
        db.query(Tag, func.count(ScanTag.id).label("scan_count"))
        .outerjoin(ScanTag, ScanTag.tag_id == Tag.id)
        .group_by(Tag.id)
    )

    if name:
        if "%" in name or "_" in name:
            query = query.filter(Tag.name.like(name))
        else:
            query = query.filter(Tag.name == name)

    results = query.order_by(Tag.name).offset(offset).limit(limit).all()

    return [
        TagResponse(
            id=tag.id,
            name=tag.name,
            created_at=tag.created_at,
            scan_count=scan_count,
        )
        for tag, scan_count in results
    ]


@router.patch("/{tag_id}", response_model=TagResponse, dependencies=[Depends(require_write)])
def rename_tag(tag_id: int, body: TagUpdate, db: Session = Depends(get_db)):
    """Rename a tag."""
    tag = db.query(Tag).filter(Tag.id == tag_id).first()
    if not tag:
        raise HTTPException(status_code=404, detail="Tag not found")

    new_name = body.name.strip()
    if not new_name:
        raise HTTPException(status_code=400, detail="Tag name cannot be empty")

    existing = db.query(Tag).filter(Tag.name == new_name, Tag.id != tag_id).first()
    if existing:
        raise HTTPException(status_code=409, detail="A tag with that name already exists")

    tag.name = new_name
    db.commit()
    db.refresh(tag)

    scan_count = db.query(func.count(ScanTag.id)).filter(ScanTag.tag_id == tag.id).scalar() or 0
    return TagResponse(id=tag.id, name=tag.name, created_at=tag.created_at, scan_count=scan_count)


@router.delete("/{tag_id}", status_code=204, dependencies=[Depends(require_write)])
def delete_tag(tag_id: int, db: Session = Depends(get_db)):
    """Delete a tag and all its scan associations."""
    tag = db.query(Tag).filter(Tag.id == tag_id).first()
    if not tag:
        raise HTTPException(status_code=404, detail="Tag not found")

    db.delete(tag)
    db.commit()
