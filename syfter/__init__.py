"""
Syfter: SBOM generation and management tool using Syft.

This tool provides:
- Syft-based SBOM generation from RPM directories, containers, and other artifacts
- CPE and PURL manipulation for product-specific metadata
- SQLite-based storage for querying across multiple products
- Export capabilities to SPDX and CycloneDX formats
- Server mode with PostgreSQL and S3 for distributed deployments
"""

__version__ = "0.9.2.0"
__author__ = "Vincent Danen"
