"""
SQLAlchemy database models.
"""

from datetime import datetime
from typing import List, Optional

from sqlalchemy import (
    Boolean,
    Column,
    Integer,
    String,
    Text,
    DateTime,
    ForeignKey,
    Index,
    UniqueConstraint,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


class Base(DeclarativeBase):
    """Base class for all models."""

    pass


class Product(Base):
    """Product model - represents a Red Hat product."""

    __tablename__ = "products"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    version: Mapped[str] = mapped_column(String(100), nullable=False)
    vendor: Mapped[str] = mapped_column(String(255), default="Red Hat")
    cpe_vendor: Mapped[str] = mapped_column(String(100), default="redhat")
    cpe_product: Mapped[Optional[str]] = mapped_column(String(255))
    purl_namespace: Mapped[str] = mapped_column(String(100), default="redhat")
    description: Mapped[Optional[str]] = mapped_column(Text)
    ps_update_stream: Mapped[Optional[str]] = mapped_column(String(100), nullable=True, index=True)
    ps_module: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    # Relationships
    scans: Mapped[List["Scan"]] = relationship(back_populates="product", cascade="all, delete-orphan")

    __table_args__ = (
        UniqueConstraint("name", "version", name="uq_product_name_version"),
    )

    @property
    def full_name(self) -> str:
        return f"{self.name}-{self.version}"


class System(Base):
    """System model - represents a host/server in infrastructure."""

    __tablename__ = "systems"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    hostname: Mapped[str] = mapped_column(String(255), nullable=False, unique=True)
    ip_address: Mapped[Optional[str]] = mapped_column(String(45))  # IPv6 max length
    tag: Mapped[Optional[str]] = mapped_column(String(255))  # For CMDB linking, grouping
    os_name: Mapped[Optional[str]] = mapped_column(String(255))  # e.g., "Red Hat Enterprise Linux"
    os_version: Mapped[Optional[str]] = mapped_column(String(100))  # e.g., "10.0"
    arch: Mapped[Optional[str]] = mapped_column(String(50))  # e.g., "x86_64"
    last_scan_at: Mapped[Optional[datetime]] = mapped_column(DateTime)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    # Relationships
    scans: Mapped[List["Scan"]] = relationship(back_populates="system", cascade="all, delete-orphan")

    __table_args__ = (
        Index("idx_system_hostname", "hostname"),
        Index("idx_system_tag", "tag"),
        Index("idx_system_ip", "ip_address"),
    )


class Scan(Base):
    """Scan model - represents a single SBOM scan."""

    __tablename__ = "scans"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    # Either product_id OR system_id should be set, not both
    product_id: Mapped[Optional[int]] = mapped_column(ForeignKey("products.id"), nullable=True)
    system_id: Mapped[Optional[int]] = mapped_column(ForeignKey("systems.id"), nullable=True)

    source_path: Mapped[str] = mapped_column(Text, nullable=False)
    source_type: Mapped[str] = mapped_column(String(50), default="directory")
    scan_timestamp: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    syft_version: Mapped[Optional[str]] = mapped_column(String(50))

    # User-provided scan label/version (for systems, defaults to scan date)
    scan_label: Mapped[Optional[str]] = mapped_column(String(100))

    # Container image metadata (for container scans)
    image_id: Mapped[Optional[str]] = mapped_column(String(100))  # sha256 of image
    image_layers_json: Mapped[Optional[str]] = mapped_column(Text)  # JSON: [{layer_id, index, source_image}]

    # Storage references (instead of storing blobs)
    original_sbom_key: Mapped[str] = mapped_column(String(500), nullable=False)
    modified_sbom_key: Mapped[str] = mapped_column(String(500), nullable=False)

    # Stats
    package_count: Mapped[int] = mapped_column(Integer, default=0)
    file_count: Mapped[int] = mapped_column(Integer, default=0)
    original_size_bytes: Mapped[int] = mapped_column(Integer, default=0)
    modified_size_bytes: Mapped[int] = mapped_column(Integer, default=0)

    # Background dependency processing status
    deps_status: Mapped[Optional[str]] = mapped_column(String(20), nullable=True)
    deps_count: Mapped[int] = mapped_column(Integer, default=0)

    # Relationships
    product: Mapped[Optional["Product"]] = relationship(back_populates="scans")
    system: Mapped[Optional["System"]] = relationship(back_populates="scans")
    packages: Mapped[List["Package"]] = relationship(back_populates="scan", cascade="all, delete-orphan")
    dependencies: Mapped[List["Dependency"]] = relationship(back_populates="scan", cascade="all, delete-orphan")
    image_layers: Mapped[List["ImageLayer"]] = relationship(back_populates="scan", cascade="all, delete-orphan")
    attestations: Mapped[List["Attestation"]] = relationship(back_populates="scan", cascade="all, delete-orphan")
    scan_tags: Mapped[List["ScanTag"]] = relationship(back_populates="scan", cascade="all, delete-orphan")

    __table_args__ = (
        Index("idx_scan_product", "product_id"),
        Index("idx_scan_system", "system_id"),
        Index("idx_scan_timestamp", "scan_timestamp"),
    )


class ImageLayer(Base):
    """ImageLayer model - maps container layer IDs to source images."""

    __tablename__ = "image_layers"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"), nullable=False)

    layer_id: Mapped[str] = mapped_column(String(100), nullable=False)  # sha256 digest
    layer_index: Mapped[int] = mapped_column(Integer, nullable=False)  # position (0=bottom)
    source_image: Mapped[Optional[str]] = mapped_column(String(500))  # image reference
    is_base: Mapped[bool] = mapped_column(Boolean, default=False)  # true if from base image
    command: Mapped[Optional[str]] = mapped_column(Text)  # Dockerfile instruction (RUN, COPY, etc.)

    # Relationships
    scan: Mapped["Scan"] = relationship(back_populates="image_layers")

    __table_args__ = (
        Index("idx_image_layer_scan", "scan_id"),
        Index("idx_image_layer_id", "layer_id"),
        Index("idx_image_layer_base", "is_base"),
        UniqueConstraint("scan_id", "layer_id", name="uq_scan_layer"),
    )


class Attestation(Base):
    """Attestation model - cosign attestation metadata for container scans."""

    __tablename__ = "attestations"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"), nullable=False)

    predicate_type: Mapped[Optional[str]] = mapped_column(String(200))
    builder_id: Mapped[Optional[str]] = mapped_column(String(500))
    build_type: Mapped[Optional[str]] = mapped_column(String(200))
    build_started_on: Mapped[Optional[datetime]] = mapped_column(DateTime)
    build_finished_on: Mapped[Optional[datetime]] = mapped_column(DateTime)
    attestation_key: Mapped[str] = mapped_column(String(500), nullable=False)

    scan: Mapped["Scan"] = relationship(back_populates="attestations")

    __table_args__ = (
        Index("idx_attestation_scan", "scan_id"),
        Index("idx_attestation_predicate", "predicate_type"),
    )


class Package(Base):
    """Package model - indexed package information for querying."""

    __tablename__ = "packages"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"), nullable=False)
    # Either product_id OR system_id should be set
    product_id: Mapped[Optional[int]] = mapped_column(ForeignKey("products.id"), nullable=True)
    system_id: Mapped[Optional[int]] = mapped_column(ForeignKey("systems.id"), nullable=True)

    name: Mapped[str] = mapped_column(String(500), nullable=False)
    version: Mapped[Optional[str]] = mapped_column(String(200))
    release: Mapped[Optional[str]] = mapped_column(String(200))
    arch: Mapped[Optional[str]] = mapped_column(String(50))
    epoch: Mapped[Optional[str]] = mapped_column(String(20))
    source_rpm: Mapped[Optional[str]] = mapped_column(String(500))
    license: Mapped[Optional[str]] = mapped_column(Text)
    purl: Mapped[Optional[str]] = mapped_column(String(1000))
    cpes: Mapped[Optional[str]] = mapped_column(Text)  # JSON array

    # Container layer tracking (for container scans)
    layer_id: Mapped[Optional[str]] = mapped_column(String(100))  # sha256 digest of layer
    layer_index: Mapped[Optional[int]] = mapped_column(Integer)  # position in layer stack (0=bottom)
    source_image: Mapped[Optional[str]] = mapped_column(String(500))  # image that introduced this package

    # Relationships
    scan: Mapped["Scan"] = relationship(back_populates="packages")
    files: Mapped[List["File"]] = relationship(back_populates="package", cascade="all, delete-orphan")

    __table_args__ = (
        Index("idx_package_name", "name"),
        Index("idx_package_product", "product_id"),
        Index("idx_package_system", "system_id"),
        Index("idx_package_purl", "purl"),
        Index("idx_package_scan", "scan_id"),
        Index("idx_package_layer", "layer_id"),
        Index("idx_package_source_image", "source_image"),
    )


class File(Base):
    """File model - indexed file information for querying."""

    __tablename__ = "files"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    package_id: Mapped[int] = mapped_column(ForeignKey("packages.id", ondelete="CASCADE"), nullable=False)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"), nullable=False)
    # Either product_id OR system_id should be set
    product_id: Mapped[Optional[int]] = mapped_column(ForeignKey("products.id"), nullable=True)
    system_id: Mapped[Optional[int]] = mapped_column(ForeignKey("systems.id"), nullable=True)

    path: Mapped[str] = mapped_column(String(1000), nullable=False)
    digest: Mapped[Optional[str]] = mapped_column(String(200))
    digest_algorithm: Mapped[Optional[str]] = mapped_column(String(20), default="sha256")

    # Relationships
    package: Mapped["Package"] = relationship(back_populates="files")

    __table_args__ = (
        Index("idx_file_path", "path"),
        Index("idx_file_product", "product_id"),
        Index("idx_file_system", "system_id"),
        Index("idx_file_digest", "digest"),
        Index("idx_file_scan", "scan_id"),
    )


class Dependency(Base):
    """Dependency model - RPM requires/provides for a package."""

    __tablename__ = "dependencies"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    package_id: Mapped[Optional[int]] = mapped_column(
        ForeignKey("packages.id", ondelete="CASCADE"), nullable=True
    )
    scan_id: Mapped[int] = mapped_column(
        ForeignKey("scans.id", ondelete="CASCADE"), nullable=False
    )
    product_id: Mapped[Optional[int]] = mapped_column(
        ForeignKey("products.id"), nullable=True
    )

    dependency_name: Mapped[str] = mapped_column(Text, nullable=False)
    dependency_version: Mapped[Optional[str]] = mapped_column(Text)
    dependency_flags: Mapped[Optional[str]] = mapped_column(String(10))  # EQ, GE, LE, GT, LT
    dependency_type: Mapped[str] = mapped_column(String(20), nullable=False)  # requires, provides

    # Relationships
    scan: Mapped["Scan"] = relationship(back_populates="dependencies")

    __table_args__ = (
        Index("idx_dep_package", "package_id"),
        Index("idx_dep_name", "dependency_name"),
        Index("idx_dep_scan", "scan_id"),
        Index("idx_dep_product", "product_id"),
        Index("idx_dep_type", "dependency_type"),
    )


class ComponentRelationship(Base):
    """Tracks product-to-product composition (e.g., container as component of layered product)."""

    __tablename__ = "component_relationships"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    parent_product_id: Mapped[int] = mapped_column(
        ForeignKey("products.id"), nullable=False
    )
    component_product_id: Mapped[int] = mapped_column(
        ForeignKey("products.id"), nullable=False
    )
    relationship_type: Mapped[str] = mapped_column(
        String(50), nullable=False
    )  # "layered" or "maintained"
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    # Relationships
    parent_product: Mapped["Product"] = relationship(foreign_keys=[parent_product_id])
    component_product: Mapped["Product"] = relationship(foreign_keys=[component_product_id])

    __table_args__ = (
        Index("idx_cr_parent", "parent_product_id"),
        Index("idx_cr_component", "component_product_id"),
        UniqueConstraint(
            "parent_product_id",
            "component_product_id",
            name="uq_parent_component",
        ),
    )


class VulcanAnalysis(Base):
    """VULCAN CVE impact analysis with layer deduplication."""

    __tablename__ = "vulcan_analyses"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    cve_id: Mapped[Optional[str]] = mapped_column(String(50))
    component: Mapped[str] = mapped_column(String(500), nullable=False)
    ps_module: Mapped[Optional[str]] = mapped_column(String(100))
    impact: Mapped[Optional[str]] = mapped_column(String(20))
    total_products: Mapped[int] = mapped_column(Integer, default=0)
    rhel_repos: Mapped[int] = mapped_column(Integer, default=0)
    base_images: Mapped[int] = mapped_column(Integer, default=0)
    layered_containers: Mapped[int] = mapped_column(Integer, default=0)
    app_layer_unique: Mapped[int] = mapped_column(Integer, default=0)
    recommended_trackers: Mapped[int] = mapped_column(Integer, default=0)
    status: Mapped[str] = mapped_column(String(20), default="active")
    analyzed_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    resolved_at: Mapped[Optional[datetime]] = mapped_column(DateTime)
    resolved_by: Mapped[Optional[str]] = mapped_column(String(100))

    trackers: Mapped[List["VulcanTracker"]] = relationship(
        back_populates="analysis", cascade="all, delete-orphan"
    )

    __table_args__ = (
        Index("idx_va_cve", "cve_id"),
        Index("idx_va_component", "component"),
        Index("idx_va_status", "status"),
    )


class VulcanTracker(Base):
    """Deduplicated tracker recommendation from a VULCAN analysis."""

    __tablename__ = "vulcan_trackers"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    analysis_id: Mapped[int] = mapped_column(
        ForeignKey("vulcan_analyses.id", ondelete="CASCADE"), nullable=False
    )
    tracker_type: Mapped[str] = mapped_column(String(20), nullable=False)
    product_name: Mapped[str] = mapped_column(String(255), nullable=False)
    product_version: Mapped[str] = mapped_column(String(100), nullable=False)
    covers_count: Mapped[int] = mapped_column(Integer, default=0)
    covered_products_json: Mapped[Optional[str]] = mapped_column(Text)
    package_version: Mapped[Optional[str]] = mapped_column(String(200))
    package_arch: Mapped[Optional[str]] = mapped_column(String(50))
    status: Mapped[str] = mapped_column(String(20), default="open")
    resolved_at: Mapped[Optional[datetime]] = mapped_column(DateTime)
    resolved_by: Mapped[Optional[str]] = mapped_column(String(100))

    analysis: Mapped["VulcanAnalysis"] = relationship(back_populates="trackers")

    __table_args__ = (
        Index("idx_vt_analysis", "analysis_id"),
        Index("idx_vt_product", "product_name", "product_version"),
    )


class ApiKey(Base):
    """API key for authentication."""

    __tablename__ = "api_keys"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    key_hash: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)  # SHA-256 hex
    key_prefix: Mapped[str] = mapped_column(String(8), nullable=False)  # First 8 chars for identification
    team_name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    is_admin: Mapped[bool] = mapped_column(Boolean, default=False)
    role: Mapped[str] = mapped_column(String(10), nullable=False, server_default="write")  # read, write, admin
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    last_used_at: Mapped[Optional[datetime]] = mapped_column(DateTime)
    expires_at: Mapped[Optional[datetime]] = mapped_column(DateTime)

    __table_args__ = (
        Index("idx_apikey_hash", "key_hash"),
        Index("idx_apikey_team", "team_name"),
    )


class Tag(Base):
    """Tag for grouping scans (e.g., by customer, product line)."""

    __tablename__ = "tags"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    name: Mapped[str] = mapped_column(String(100), nullable=False, unique=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    scan_tags: Mapped[List["ScanTag"]] = relationship(back_populates="tag", cascade="all, delete-orphan")


class ScanTag(Base):
    """Many-to-many join between scans and tags."""

    __tablename__ = "scan_tags"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"), nullable=False)
    tag_id: Mapped[int] = mapped_column(ForeignKey("tags.id", ondelete="CASCADE"), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    scan: Mapped["Scan"] = relationship(back_populates="scan_tags")
    tag: Mapped["Tag"] = relationship(back_populates="scan_tags")

    __table_args__ = (
        UniqueConstraint("scan_id", "tag_id", name="uq_scan_tag"),
        Index("idx_scan_tags_scan_id", "scan_id"),
        Index("idx_scan_tags_tag_id", "tag_id"),
    )


class AccessLog(Base):
    """API access log for audit trail."""

    __tablename__ = "access_log"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    method: Mapped[str] = mapped_column(String(10), nullable=False)
    path: Mapped[str] = mapped_column(String(500), nullable=False)
    status_code: Mapped[int] = mapped_column(Integer, nullable=False)
    response_ms: Mapped[int] = mapped_column(Integer, nullable=False)
    key_prefix: Mapped[Optional[str]] = mapped_column(String(8))
    team_name: Mapped[Optional[str]] = mapped_column(String(255))
    client_ip: Mapped[Optional[str]] = mapped_column(String(45))

    __table_args__ = (
        Index("idx_access_log_timestamp", "timestamp"),
        Index("idx_access_log_team", "team_name"),
    )
