"""
Storage module - SQLite database for SBOM storage and querying.
"""

import gzip
import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
from typing import Optional, Iterator

from rich.console import Console

from .models import Product, ScanRecord, PackageInfo, FileInfo

console = Console()


def _compress_json(data: dict) -> bytes:
    """Compress a dictionary to gzipped JSON bytes."""
    json_str = json.dumps(data)
    return gzip.compress(json_str.encode("utf-8"))


# Maximum decompressed size to prevent zip bombs (2GB)
_MAX_DECOMPRESSED_SIZE = 4 * 1024 * 1024 * 1024  # 4GB for large distros like RHEL


def _safe_decompress(data: bytes, max_size: int = _MAX_DECOMPRESSED_SIZE) -> bytes:
    """
    Safely decompress gzip data with size limit to prevent decompression bombs.

    Args:
        data: Compressed gzip data
        max_size: Maximum allowed decompressed size in bytes

    Returns:
        Decompressed bytes

    Raises:
        ValueError: If decompressed size exceeds limit
    """
    import io

    decompressor = gzip.GzipFile(fileobj=io.BytesIO(data))
    chunks = []
    total_size = 0

    while True:
        chunk = decompressor.read(1024 * 1024)  # Read 1MB at a time
        if not chunk:
            break
        total_size += len(chunk)
        if total_size > max_size:
            raise ValueError(
                f"Decompressed data ({total_size // (1024*1024)}MB so far) exceeds maximum size limit of {max_size // (1024*1024*1024)}GB"
            )
        chunks.append(chunk)

    return b''.join(chunks)


def _decompress_json(data: bytes) -> dict:
    """Decompress gzipped JSON bytes to a dictionary."""
    json_str = _safe_decompress(data).decode("utf-8")
    return json.loads(json_str)

DEFAULT_DB_PATH = Path("~/.syfter/syfter.db").expanduser()


class Storage:
    """SQLite-based storage for SBOMs and package data."""

    def __init__(self, db_path: Optional[Path] = None):
        """
        Initialize storage with database path.

        Args:
            db_path: Path to SQLite database (defaults to ~/.syfter/syfter.db)
        """
        self.db_path = db_path or DEFAULT_DB_PATH
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    @contextmanager
    def _get_connection(self) -> Iterator[sqlite3.Connection]:
        """Get a database connection with row factory."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        # Enable foreign keys
        conn.execute("PRAGMA foreign_keys = ON")
        try:
            yield conn
        finally:
            conn.close()

    def _init_db(self) -> None:
        """Initialize database schema."""
        with self._get_connection() as conn:
            cursor = conn.cursor()

            # Products table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS products (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL,
                    version TEXT NOT NULL,
                    vendor TEXT DEFAULT 'Red Hat',
                    cpe_vendor TEXT DEFAULT 'redhat',
                    cpe_product TEXT,
                    purl_namespace TEXT DEFAULT 'redhat',
                    description TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    UNIQUE(name, version)
                )
            """)

            # Scans table - stores the full SBOM as compressed JSON (gzip)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS scans (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    product_id INTEGER NOT NULL,
                    source_path TEXT NOT NULL,
                    source_type TEXT DEFAULT 'directory',
                    scan_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    syft_version TEXT,
                    original_sbom BLOB NOT NULL,
                    modified_sbom BLOB NOT NULL,
                    package_count INTEGER DEFAULT 0,
                    file_count INTEGER DEFAULT 0,
                    image_layers_json TEXT,
                    FOREIGN KEY (product_id) REFERENCES products(id)
                )
            """)

            # Packages table - indexed for querying
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS packages (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id INTEGER NOT NULL,
                    product_id INTEGER NOT NULL,
                    name TEXT NOT NULL,
                    version TEXT,
                    release TEXT,
                    arch TEXT,
                    epoch TEXT,
                    source_rpm TEXT,
                    license TEXT,
                    purl TEXT,
                    cpes TEXT,
                    layer_id TEXT,
                    layer_index INTEGER,
                    source_image TEXT,
                    FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE,
                    FOREIGN KEY (product_id) REFERENCES products(id)
                )
            """)

            # Files table - indexed for querying
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS files (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    package_id INTEGER NOT NULL,
                    scan_id INTEGER NOT NULL,
                    product_id INTEGER NOT NULL,
                    path TEXT NOT NULL,
                    digest TEXT,
                    digest_algorithm TEXT DEFAULT 'sha256',
                    FOREIGN KEY (package_id) REFERENCES packages(id) ON DELETE CASCADE,
                    FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE,
                    FOREIGN KEY (product_id) REFERENCES products(id)
                )
            """)

            # Create indexes for common queries
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_packages_name ON packages(name)
            """)
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_packages_product ON packages(product_id)
            """)
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_packages_purl ON packages(purl)
            """)
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_files_path ON files(path)
            """)
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_files_product ON files(product_id)
            """)
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_files_digest ON files(digest)
            """)

            conn.commit()

    def get_or_create_product(self, product: Product) -> int:
        """
        Get or create a product record.

        Args:
            product: Product object

        Returns:
            int: Product ID
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()

            # Try to find existing
            cursor.execute(
                "SELECT id FROM products WHERE name = ? AND version = ?",
                (product.name, product.version),
            )
            row = cursor.fetchone()
            if row:
                return row["id"]

            # Create new
            cursor.execute(
                """
                INSERT INTO products (name, version, vendor, cpe_vendor, cpe_product, purl_namespace, description)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    product.name,
                    product.version,
                    product.vendor,
                    product.cpe_vendor,
                    product.cpe_product,
                    product.purl_namespace,
                    product.description,
                ),
            )
            conn.commit()
            return cursor.lastrowid

    def store_scan(
        self,
        product_id: int,
        source_path: str,
        source_type: str,
        syft_version: str,
        original_sbom: dict,
        modified_sbom: dict,
        packages: list[dict],
        image_layers: Optional[list[dict]] = None,
    ) -> int:
        """
        Store a scan result with indexed package data.

        If a scan already exists for this product, it will be replaced.

        Args:
            product_id: Product ID
            source_path: Path to scanned source
            source_type: Type of source (directory, container, etc.)
            syft_version: Version of syft used
            original_sbom: Original syft-json SBOM
            modified_sbom: Modified SBOM with product metadata
            packages: List of extracted package dictionaries
            image_layers: Optional list of container layer info

        Returns:
            int: Scan ID
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()

            # Delete existing scan for this product (replace behavior)
            cursor.execute(
                "SELECT id FROM scans WHERE product_id = ?",
                (product_id,)
            )
            existing = cursor.fetchone()
            if existing:
                existing_scan_id = existing[0]
                # Delete files, packages, and scan (cascading would be nice but SQLite...)
                cursor.execute("DELETE FROM files WHERE scan_id = ?", (existing_scan_id,))
                cursor.execute("DELETE FROM packages WHERE scan_id = ?", (existing_scan_id,))
                cursor.execute("DELETE FROM scans WHERE id = ?", (existing_scan_id,))
                console.print(f"[dim]Replacing existing scan #{existing_scan_id}[/dim]")

            # Count files
            file_count = sum(len(pkg.get("files", [])) for pkg in packages)

            # Compress SBOMs for storage
            original_sbom_compressed = _compress_json(original_sbom)
            modified_sbom_compressed = _compress_json(modified_sbom)

            console.print(
                f"[dim]Compressed SBOMs: "
                f"original {len(original_sbom_compressed) / 1024 / 1024:.1f}MB, "
                f"modified {len(modified_sbom_compressed) / 1024 / 1024:.1f}MB[/dim]"
            )

            # Serialize image layers to JSON if provided
            image_layers_json_str = None
            if image_layers:
                image_layers_json_str = json.dumps(image_layers)

            # Insert scan record
            cursor.execute(
                """
                INSERT INTO scans (product_id, source_path, source_type, syft_version,
                                   original_sbom, modified_sbom, package_count, file_count, image_layers_json)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    product_id,
                    source_path,
                    source_type,
                    syft_version,
                    original_sbom_compressed,
                    modified_sbom_compressed,
                    len(packages),
                    file_count,
                    image_layers_json_str,
                ),
            )
            scan_id = cursor.lastrowid

            # Insert packages and files
            for pkg in packages:
                cursor.execute(
                    """
                    INSERT INTO packages (scan_id, product_id, name, version, release,
                                         arch, epoch, source_rpm, license, purl, cpes,
                                         layer_id, layer_index, source_image)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        scan_id,
                        product_id,
                        pkg.get("name", ""),
                        pkg.get("version", ""),
                        pkg.get("release", ""),
                        pkg.get("arch", ""),
                        pkg.get("epoch", ""),
                        pkg.get("source_rpm", ""),
                        pkg.get("license", ""),
                        pkg.get("purl", ""),
                        pkg.get("cpes", "[]"),
                        pkg.get("layer_id"),
                        pkg.get("layer_index"),
                        pkg.get("source_image"),
                    ),
                )
                package_id = cursor.lastrowid

                # Insert files
                for f in pkg.get("files", []):
                    cursor.execute(
                        """
                        INSERT INTO files (package_id, scan_id, product_id, path, digest, digest_algorithm)
                        VALUES (?, ?, ?, ?, ?, ?)
                        """,
                        (
                            package_id,
                            scan_id,
                            product_id,
                            f.get("path", ""),
                            f.get("digest", ""),
                            f.get("digest_algorithm", "sha256"),
                        ),
                    )

            conn.commit()
            console.print(
                f"[green]Stored scan #{scan_id}: {len(packages)} packages, {file_count} files[/green]"
            )
            return scan_id

    def get_product_sbom(self, product_name: str, product_version: str) -> Optional[dict]:
        """
        Get the full modified SBOM for a product.

        Args:
            product_name: Product name (e.g., "rhel")
            product_version: Product version (e.g., "10.0")

        Returns:
            dict: Modified SBOM or None if not found
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT s.modified_sbom
                FROM scans s
                JOIN products p ON s.product_id = p.id
                WHERE p.name = ? AND p.version = ?
                ORDER BY s.scan_timestamp DESC
                LIMIT 1
                """,
                (product_name, product_version),
            )
            row = cursor.fetchone()
            if row:
                return _decompress_json(row["modified_sbom"])
            return None

    def get_product_layers(self, product_name: str, product_version: str) -> Optional[list[dict]]:
        """
        Get the container layer chain for a product.

        Args:
            product_name: Product name
            product_version: Product version

        Returns:
            list: Layer chain info or None if not a container scan
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT s.image_layers_json, s.source_path, s.source_type
                FROM scans s
                JOIN products p ON s.product_id = p.id
                WHERE p.name = ? AND p.version = ?
                ORDER BY s.scan_timestamp DESC
                LIMIT 1
                """,
                (product_name, product_version),
            )
            row = cursor.fetchone()
            if row and row["image_layers_json"]:
                layers = json.loads(row["image_layers_json"])
                return {
                    "layers": layers,
                    "source_path": row["source_path"],
                    "source_type": row["source_type"],
                }
            return None

    def get_all_product_sboms(self, product_name: str, product_version: str) -> list[dict]:
        """
        Get all SBOMs for a product (in case of multiple scans).

        Args:
            product_name: Product name
            product_version: Product version

        Returns:
            list: List of SBOM dictionaries
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT s.modified_sbom, s.source_path, s.scan_timestamp
                FROM scans s
                JOIN products p ON s.product_id = p.id
                WHERE p.name = ? AND p.version = ?
                ORDER BY s.scan_timestamp DESC
                """,
                (product_name, product_version),
            )
            return [
                {
                    "sbom": _decompress_json(row["modified_sbom"]),
                    "source_path": row["source_path"],
                    "scan_timestamp": row["scan_timestamp"],
                }
                for row in cursor.fetchall()
            ]

    def search_packages(
        self,
        name_pattern: Optional[str] = None,
        pkg_version: Optional[str] = None,
        product_name: Optional[str] = None,
        product_version: Optional[str] = None,
        limit: int = 100,
    ) -> list[dict]:
        """
        Search for packages across all products.

        Args:
            name_pattern: SQL LIKE pattern for package name (use % as wildcard)
            pkg_version: SQL LIKE pattern for package version (use % as wildcard)
            product_name: Filter by product name
            product_version: Filter by product version
            limit: Maximum results to return

        Returns:
            list: List of matching packages with product info
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()

            query = """
                SELECT pkg.*, p.name as product_name, p.version as product_version
                FROM packages pkg
                JOIN products p ON pkg.product_id = p.id
                WHERE 1=1
            """
            params = []

            if name_pattern:
                query += " AND pkg.name LIKE ?"
                params.append(name_pattern)

            if pkg_version:
                query += " AND pkg.version LIKE ?"
                params.append(pkg_version)

            if product_name:
                if "%" in product_name or "_" in product_name:
                    query += " AND p.name LIKE ?"
                else:
                    query += " AND p.name = ?"
                params.append(product_name)

            if product_version:
                if "%" in product_version or "_" in product_version:
                    query += " AND p.version LIKE ?"
                else:
                    query += " AND p.version = ?"
                params.append(product_version)

            query += " ORDER BY pkg.name LIMIT ?"
            params.append(limit)

            cursor.execute(query, params)
            return [dict(row) for row in cursor.fetchall()]

    def search_files(
        self,
        path_pattern: Optional[str] = None,
        digest: Optional[str] = None,
        product_name: Optional[str] = None,
        product_version: Optional[str] = None,
        limit: int = 100,
    ) -> list[dict]:
        """
        Search for files across all products.

        Args:
            path_pattern: SQL LIKE pattern for file path
            digest: Exact digest match
            product_name: Filter by product name
            product_version: Filter by product version
            limit: Maximum results to return

        Returns:
            list: List of matching files with package and product info
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()

            query = """
                SELECT f.*, pkg.name as package_name, pkg.version as package_version,
                       p.name as product_name, p.version as product_version
                FROM files f
                JOIN packages pkg ON f.package_id = pkg.id
                JOIN products p ON f.product_id = p.id
                WHERE 1=1
            """
            params = []

            if path_pattern:
                query += " AND f.path LIKE ?"
                params.append(path_pattern)

            if digest:
                query += " AND f.digest = ?"
                params.append(digest)

            if product_name:
                if "%" in product_name or "_" in product_name:
                    query += " AND p.name LIKE ?"
                else:
                    query += " AND p.name = ?"
                params.append(product_name)

            if product_version:
                if "%" in product_version or "_" in product_version:
                    query += " AND p.version LIKE ?"
                else:
                    query += " AND p.version = ?"
                params.append(product_version)

            query += " ORDER BY f.path LIMIT ?"
            params.append(limit)

            cursor.execute(query, params)
            return [dict(row) for row in cursor.fetchall()]

    def list_products(self) -> list[dict]:
        """
        List all products in the database.

        Returns:
            list: List of product dictionaries
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()
            # Use a subquery to get the source_type from the most recent scan
            cursor.execute("""
                SELECT p.*, COUNT(DISTINCT s.id) as scan_count,
                       SUM(s.package_count) as total_packages,
                       SUM(s.file_count) as total_files,
                       (SELECT source_type FROM scans 
                        WHERE product_id = p.id 
                        ORDER BY scan_timestamp DESC LIMIT 1) as source_type
                FROM products p
                LEFT JOIN scans s ON p.id = s.product_id
                GROUP BY p.id
                ORDER BY p.name, p.version
            """)
            return [dict(row) for row in cursor.fetchall()]

    def list_scans(self, product_name: Optional[str] = None) -> list[dict]:
        """
        List all scans, optionally filtered by product.

        Args:
            product_name: Optional product name filter

        Returns:
            list: List of scan dictionaries
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()

            query = """
                SELECT s.id, s.source_path, s.source_type, s.scan_timestamp,
                       s.syft_version, s.package_count, s.file_count,
                       p.name as product_name, p.version as product_version
                FROM scans s
                JOIN products p ON s.product_id = p.id
            """
            params = []

            if product_name:
                query += " WHERE p.name = ?"
                params.append(product_name)

            query += " ORDER BY s.scan_timestamp DESC"

            cursor.execute(query, params)
            return [dict(row) for row in cursor.fetchall()]

    def delete_scan(self, scan_id: int) -> bool:
        """
        Delete a scan and its associated packages and files.

        Args:
            scan_id: Scan ID to delete

        Returns:
            bool: True if deleted, False if not found
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM scans WHERE id = ?", (scan_id,))
            conn.commit()
            return cursor.rowcount > 0

    def delete_product(self, product_name: str, product_version: str) -> bool:
        """
        Delete a product and all its associated scans, packages, and files.

        Args:
            product_name: Product name
            product_version: Product version

        Returns:
            bool: True if deleted, False if not found
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()

            # Find the product
            cursor.execute(
                "SELECT id FROM products WHERE name = ? AND version = ?",
                (product_name, product_version)
            )
            row = cursor.fetchone()
            if not row:
                return False

            product_id = row["id"]

            # Delete in order: files -> packages -> scans -> product
            # (due to foreign key constraints)
            cursor.execute("DELETE FROM files WHERE product_id = ?", (product_id,))
            cursor.execute("DELETE FROM packages WHERE product_id = ?", (product_id,))
            cursor.execute("DELETE FROM scans WHERE product_id = ?", (product_id,))
            cursor.execute("DELETE FROM products WHERE id = ?", (product_id,))
            conn.commit()
            return True

    def get_stats(self) -> dict:
        """
        Get database statistics.

        Returns:
            dict: Statistics about the database
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()

            cursor.execute("SELECT COUNT(*) as count FROM products")
            product_count = cursor.fetchone()["count"]

            # Check if systems table exists (may not exist in older DBs)
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='systems'")
            if cursor.fetchone():
                cursor.execute("SELECT COUNT(*) as count FROM systems")
                system_count = cursor.fetchone()["count"]
            else:
                system_count = 0

            cursor.execute("SELECT COUNT(*) as count FROM scans")
            scan_count = cursor.fetchone()["count"]

            cursor.execute("SELECT COUNT(*) as count FROM packages")
            package_count = cursor.fetchone()["count"]

            cursor.execute("SELECT COUNT(*) as count FROM files")
            file_count = cursor.fetchone()["count"]

            return {
                "products": product_count,
                "systems": system_count,
                "scans": scan_count,
                "packages": package_count,
                "files": file_count,
                "database_path": str(self.db_path),
            }

    def list_all_packages(
        self,
        product_name: str,
        product_version: str,
    ) -> Iterator[dict]:
        """
        List all packages for a product version (streaming).

        Args:
            product_name: Product name
            product_version: Product version

        Yields:
            dict: Package info (name, version, arch, purl, source_image, layer_id)
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()

            # Check if layer columns exist (for backward compatibility)
            cursor.execute("PRAGMA table_info(packages)")
            columns = {row[1] for row in cursor.fetchall()}
            has_layer_cols = "source_image" in columns and "layer_id" in columns

            if has_layer_cols:
                cursor.execute(
                    """
                    SELECT pkg.name, pkg.version, pkg.release, pkg.arch, pkg.purl,
                           pkg.source_image, pkg.layer_id
                    FROM packages pkg
                    JOIN products p ON pkg.product_id = p.id
                    WHERE p.name = ? AND p.version = ?
                    ORDER BY pkg.name
                    """,
                    (product_name, product_version),
                )
            else:
                cursor.execute(
                    """
                    SELECT pkg.name, pkg.version, pkg.release, pkg.arch, pkg.purl,
                           NULL as source_image, NULL as layer_id
                    FROM packages pkg
                    JOIN products p ON pkg.product_id = p.id
                    WHERE p.name = ? AND p.version = ?
                    ORDER BY pkg.name
                    """,
                    (product_name, product_version),
                )
            for row in cursor:
                yield dict(row)

    def list_all_files(
        self,
        product_name: str,
        product_version: str,
    ) -> Iterator[str]:
        """
        List all file paths for a product version (streaming).

        Args:
            product_name: Product name
            product_version: Product version

        Yields:
            str: File path
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT f.path
                FROM files f
                JOIN products p ON f.product_id = p.id
                WHERE p.name = ? AND p.version = ?
                ORDER BY f.path
                """,
                (product_name, product_version),
            )
            for row in cursor:
                yield row["path"]
