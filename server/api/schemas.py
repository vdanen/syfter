"""
Pydantic schemas for API request/response validation.
"""

from datetime import datetime
from typing import List, Optional

from pydantic import BaseModel, Field


# System schemas (infrastructure mode)
class SystemCreate(BaseModel):
    """Schema for creating/updating a system."""

    hostname: str = Field(..., description="System hostname")
    ip_address: Optional[str] = Field(default=None, description="IP address")
    tag: Optional[str] = Field(default=None, description="Tag for grouping/CMDB linking")
    os_name: Optional[str] = Field(default=None, description="OS name (e.g., 'Red Hat Enterprise Linux')")
    os_version: Optional[str] = Field(default=None, description="OS version (e.g., '10.0')")
    arch: Optional[str] = Field(default=None, description="Architecture (e.g., 'x86_64')")


class SystemResponse(BaseModel):
    """Schema for system response."""

    id: int
    hostname: str
    ip_address: Optional[str]
    tag: Optional[str]
    os_name: Optional[str]
    os_version: Optional[str]
    arch: Optional[str]
    last_scan_at: Optional[datetime]
    created_at: datetime
    scan_count: int = 0
    total_packages: int = 0
    total_files: int = 0

    class Config:
        from_attributes = True


# Product schemas
class ProductCreate(BaseModel):
    """Schema for creating a product."""

    name: str = Field(..., description="Product name (e.g., 'rhel')")
    version: str = Field(..., description="Product version (e.g., '10.0')")
    vendor: str = Field(default="Red Hat", description="Vendor name")
    cpe_vendor: str = Field(default="redhat", description="CPE vendor string")
    cpe_product: Optional[str] = Field(default=None, description="CPE product string")
    purl_namespace: str = Field(default="redhat", description="PURL namespace")
    description: Optional[str] = Field(default=None, description="Product description")
    ps_update_stream: Optional[str] = Field(default=None, description="OSIDB ps_update_stream (e.g., rhel-9.6.z)")
    ps_module: Optional[str] = Field(default=None, description="OSIDB ps_module (e.g., rhel-9)")


class ProductResponse(BaseModel):
    """Schema for product response."""

    id: int
    name: str
    version: str
    vendor: str
    cpe_vendor: str
    cpe_product: Optional[str]
    purl_namespace: str
    description: Optional[str]
    ps_update_stream: Optional[str] = None
    ps_module: Optional[str] = None
    created_at: datetime
    scan_count: int = 0
    total_packages: int = 0
    total_files: int = 0
    source_type: Optional[str] = None

    class Config:
        from_attributes = True


class ProductUpdate(BaseModel):
    """Schema for updating a product."""

    name: Optional[str] = Field(default=None, description="New product name")
    version: Optional[str] = Field(default=None, description="New product version")
    description: Optional[str] = Field(default=None, description="New description")
    ps_update_stream: Optional[str] = Field(default=None, description="New ps_update_stream")
    ps_module: Optional[str] = Field(default=None, description="New ps_module")


class TagUpdate(BaseModel):
    """Schema for renaming a tag."""

    name: str = Field(..., description="New tag name")


# Scan schemas
class ScanCreate(BaseModel):
    """Schema for creating a scan."""

    product_name: str = Field(..., description="Product name")
    product_version: str = Field(..., description="Product version")
    source_path: str = Field(..., description="Source path that was scanned")
    source_type: str = Field(default="directory", description="Type of source")
    syft_version: Optional[str] = Field(default=None, description="Syft version used")


class ScanMetadata(BaseModel):
    """Schema for scan metadata sent with upload."""

    product_name: str
    product_version: str
    source_path: str
    source_type: str = "directory"
    syft_version: Optional[str] = None
    package_count: int = 0
    file_count: int = 0


class ScanResponse(BaseModel):
    """Schema for scan response."""

    id: int
    product_id: int
    product_name: str
    product_version: str
    source_path: str
    source_type: str
    scan_timestamp: datetime
    syft_version: Optional[str]
    package_count: int
    file_count: int
    original_size_bytes: int
    modified_size_bytes: int
    deps_status: Optional[str] = None
    deps_count: int = 0
    tags: List[str] = []

    class Config:
        from_attributes = True


class ImportResponse(BaseModel):
    """Schema for SBOM import response."""

    id: int
    product_id: int
    product_name: str
    product_version: str
    source_path: str
    source_type: str
    scan_timestamp: datetime
    syft_version: Optional[str]
    package_count: int
    file_count: int
    original_size_bytes: int
    modified_size_bytes: int
    sbom_format: str = Field(description="Detected SBOM format (spdx, cyclonedx, syft-json)")
    tags: list[str] = Field(default_factory=list, description="Applied tag names")

    class Config:
        from_attributes = True


class ScanUploadResponse(BaseModel):
    """Response with presigned URLs for scan upload."""

    scan_id: int
    original_upload_url: str
    modified_upload_url: str
    packages_upload_url: str  # URL to POST package index


# Package schemas
class PackageCreate(BaseModel):
    """Schema for package index entry."""

    name: str
    version: Optional[str] = None
    release: Optional[str] = None
    arch: Optional[str] = None
    epoch: Optional[str] = None
    source_rpm: Optional[str] = None
    license: Optional[str] = None
    purl: Optional[str] = None
    cpes: Optional[str] = None  # JSON array
    files: List["FileCreate"] = []


class FileCreate(BaseModel):
    """Schema for file index entry."""

    path: str
    digest: Optional[str] = None
    digest_algorithm: Optional[str] = "sha256"


class PackageResponse(BaseModel):
    """Schema for package search response."""

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
    product_name: str
    product_version: str
    # Container layer info (may be None for non-container scans)
    layer_id: Optional[str] = None
    layer_index: Optional[int] = None
    source_image: Optional[str] = None
    tags: List[str] = []

    class Config:
        from_attributes = True


class FileResponse(BaseModel):
    """Schema for file search response."""

    id: int
    path: str
    digest: Optional[str]
    digest_algorithm: Optional[str]
    package_name: str
    package_version: Optional[str]
    product_name: str
    product_version: str
    # Container layer info (may be None for non-container scans)
    source_image: Optional[str] = None

    class Config:
        from_attributes = True


# Query schemas
class PackageQuery(BaseModel):
    """Schema for package search query."""

    name: Optional[str] = Field(default=None, description="Package name pattern (use % as wildcard)")
    product_name: Optional[str] = Field(default=None, description="Filter by product name")
    product_version: Optional[str] = Field(default=None, description="Filter by product version")
    limit: int = Field(default=100, le=1000, description="Maximum results")
    offset: int = Field(default=0, description="Offset for pagination")


class FileQuery(BaseModel):
    """Schema for file search query."""

    path: Optional[str] = Field(default=None, description="File path pattern (use % as wildcard)")
    digest: Optional[str] = Field(default=None, description="File digest (exact match)")
    product_name: Optional[str] = Field(default=None, description="Filter by product name")
    product_version: Optional[str] = Field(default=None, description="Filter by product version")
    limit: int = Field(default=100, le=1000, description="Maximum results")
    offset: int = Field(default=0, description="Offset for pagination")


# Export schemas
class ExportRequest(BaseModel):
    """Schema for SBOM export request."""

    product_name: str
    product_version: str
    format: str = Field(default="spdx-json", description="Output format")


class ExportResponse(BaseModel):
    """Schema for export response with download URL."""

    download_url: str
    format: str
    expires_in: int = 3600


# Stats schemas
class StatsResponse(BaseModel):
    """Schema for database statistics."""

    products: int
    systems: int = 0
    scans: int
    packages: int
    files: int
    dependencies: int = 0
    component_relationships: int = 0
    storage_type: str
    database_type: str


# Dependency schemas
class DependencyResponse(BaseModel):
    """Schema for dependency search response."""

    id: int
    package_id: Optional[int]
    package_name: Optional[str] = None
    package_version: Optional[str] = None
    package_arch: Optional[str] = None
    dependency_name: str
    dependency_version: Optional[str]
    dependency_flags: Optional[str]
    dependency_type: str
    product_name: str
    product_version: str

    class Config:
        from_attributes = True


# Component relationship schemas
class ComponentRelationshipCreate(BaseModel):
    """Schema for creating a component relationship."""

    parent_product_name: str = Field(..., description="Parent/layered product name")
    parent_product_version: str = Field(..., description="Parent product version")
    component_product_name: str = Field(..., description="Component product name")
    component_product_version: str = Field(..., description="Component product version")
    relationship_type: str = Field(
        default="layered",
        description="'layered' (included without modification) or 'maintained' (Red Hat owns maintenance)",
    )


class ComponentRelationshipResponse(BaseModel):
    """Schema for component relationship response."""

    id: int
    parent_product_name: str
    parent_product_version: str
    component_product_name: str
    component_product_version: str
    relationship_type: str
    created_at: datetime

    class Config:
        from_attributes = True


# Tag schemas
class TagCreate(BaseModel):
    """Schema for adding tags to a scan."""

    tags: List[str] = Field(..., description="Tag names to add")


class TagResponse(BaseModel):
    """Schema for tag response."""

    id: int
    name: str
    created_at: datetime
    scan_count: int = 0

    class Config:
        from_attributes = True


class PackageFrequencyResponse(BaseModel):
    """Schema for package version frequency across SBOMs."""

    version: str
    sbom_count: int = Field(description="Number of SBOMs containing this version")
    products: List[str] = Field(description="Product names containing this version")

    class Config:
        from_attributes = True


# VULCAN analysis schemas
class VulcanAnalyzeRequest(BaseModel):
    """Request to run a VULCAN CVE impact analysis."""

    component: str = Field(..., description="RPM package name (e.g., 'openssl')")
    ps_module: Optional[str] = Field(default=None, description="OSIDB ps_module (e.g., 'rhel-9')")
    cve_id: Optional[str] = Field(default=None, description="CVE identifier for labeling")
    impact: Optional[str] = Field(default=None, description="CRITICAL/IMPORTANT/MODERATE/LOW")


class VulcanTrackerResponse(BaseModel):
    """A deduplicated tracker recommendation."""

    id: int
    tracker_type: str
    product_name: str
    product_version: str
    covers_count: int
    covered_products: List[str]
    package_version: Optional[str]
    package_arch: Optional[str]
    status: str

    class Config:
        from_attributes = True


class VulcanAnalysisSummary(BaseModel):
    """Summary counts for a VULCAN analysis."""

    total_products: int
    rhel_repos: int
    base_images: int
    layered_containers: int
    app_layer_unique: int
    recommended_trackers: int
    dedup_ratio: str


class VulcanAnalysisResponse(BaseModel):
    """Full VULCAN analysis result."""

    id: int
    cve_id: Optional[str]
    component: str
    ps_module: Optional[str]
    impact: Optional[str]
    analyzed_at: datetime
    status: str
    resolved_at: Optional[datetime] = None
    resolved_by: Optional[str] = None
    summary: VulcanAnalysisSummary
    trackers: List[VulcanTrackerResponse]

    class Config:
        from_attributes = True


class VulcanAnalysisListItem(BaseModel):
    """Brief analysis entry for list views."""

    id: int
    cve_id: Optional[str]
    component: str
    ps_module: Optional[str]
    impact: Optional[str]
    analyzed_at: datetime
    status: str
    total_products: int
    recommended_trackers: int

    class Config:
        from_attributes = True


class VulcanResolveRequest(BaseModel):
    """Request to resolve a VULCAN analysis."""

    resolved_by: str = Field(..., description="RHSA ID (e.g., 'RHSA-2026:1234')")


class RemoteScanCreate(BaseModel):
    """Schema for creating a server-side remote scan job."""

    url: str = Field(..., description="HTTP/HTTPS URL to an RPM repository directory")
    product_name: str = Field(..., description="Product name (e.g., 'rhel')")
    product_version: str = Field(..., description="Product version (e.g., '10.1')")
    description: str = Field(default="", description="Product description")
    skip_files: bool = Field(default=True, description="Skip file indexing (recommended for large repos)")
    exclude_debug: bool = Field(default=True, description="Exclude debuginfo/debugsource packages")


# Update forward references
PackageCreate.model_rebuild()
