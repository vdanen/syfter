"""
API client for communicating with the Syfter server.
"""

import gzip
import io
import json
import os
import time
from pathlib import Path
from typing import Optional, Tuple, List
from urllib.parse import urljoin

import httpx
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn

console = Console()


class APIError(Exception):
    """Raised when an API call fails."""

    def __init__(self, status_code: int, detail: str):
        self.status_code = status_code
        self.detail = detail
        super().__init__(f"API error {status_code}: {detail}")


def build_tsv_files(packages: list) -> Tuple[bytes, bytes, int, int]:
    """
    Build gzip-compressed TSV files from package data.

    Args:
        packages: List of package dicts with 'files' key

    Returns:
        Tuple of (packages_tsv_gz, files_tsv_gz, package_count, file_count)
    """
    packages_buffer = io.StringIO()
    files_buffer = io.StringIO()

    package_count = 0
    file_count = 0

    for pkg in packages:
        # Package TSV: name, version, release, arch, epoch, source_rpm, license, purl, cpes, layer_id, layer_index, source_image
        layer_index = pkg.get("layer_index")
        pkg_fields = [
            pkg.get("name", "") or "",
            pkg.get("version") or "\\N",
            pkg.get("release") or "\\N",
            pkg.get("arch") or "\\N",
            pkg.get("epoch") or "\\N",
            pkg.get("source_rpm") or "\\N",
            pkg.get("license") or "\\N",
            pkg.get("purl") or "\\N",
            pkg.get("cpes") or "\\N",
            pkg.get("layer_id") or "\\N",
            str(layer_index) if layer_index is not None else "\\N",
            pkg.get("source_image") or "\\N",
        ]
        # Escape tabs and newlines in fields
        pkg_fields = [f.replace("\t", " ").replace("\n", " ").replace("\r", "") for f in pkg_fields]
        packages_buffer.write("\t".join(pkg_fields) + "\n")
        package_count += 1

        # Files TSV: pkg_name, pkg_version, pkg_arch, path, digest, digest_algo
        pkg_name = pkg.get("name", "")
        pkg_version = pkg.get("version") or "\\N"
        pkg_arch = pkg.get("arch") or "\\N"

        for f in pkg.get("files", []):
            file_fields = [
                pkg_name,
                pkg_version,
                pkg_arch,
                f.get("path", ""),
                f.get("digest") or "\\N",
                f.get("digest_algorithm") or "\\N",
            ]
            file_fields = [fld.replace("\t", " ").replace("\n", " ").replace("\r", "") for fld in file_fields]
            files_buffer.write("\t".join(file_fields) + "\n")
            file_count += 1

    # Compress
    packages_tsv_gz = gzip.compress(packages_buffer.getvalue().encode('utf-8'))
    files_tsv_gz = gzip.compress(files_buffer.getvalue().encode('utf-8')) if file_count > 0 else b""

    return packages_tsv_gz, files_tsv_gz, package_count, file_count


class SyfterClient:
    """Client for the Syfter API."""

    def __init__(self, base_url: str, timeout: float = 600.0):
        """
        Initialize the client.

        Args:
            base_url: Base URL of the API server (e.g., http://localhost:8000)
            timeout: Request timeout in seconds (default: 600 for large uploads)
        """
        self.base_url = base_url.rstrip("/")
        self.api_url = f"{self.base_url}/api/v1"
        self.timeout = timeout

        # Build default headers
        headers = {}

        # Support API key auth via SYFTER_API_KEY env var
        api_key = os.environ.get("SYFTER_API_KEY")
        if api_key:
            headers["X-API-Key"] = api_key

        self._api_key = api_key
        self._headers = headers

        # Use longer timeouts for uploads - large SBOMs can take minutes
        # Force HTTP/1.1 for large uploads - HTTP/2 can have issues with very large requests
        self.client = httpx.Client(
            timeout=httpx.Timeout(timeout, connect=30.0, read=timeout, write=timeout),
            http2=False,  # Disable HTTP/2 for more reliable large uploads
            headers=headers,
        )

    def _url(self, path: str) -> str:
        """Build full URL for an API path."""
        return f"{self.api_url}{path}"

    def _handle_response(self, response: httpx.Response) -> dict:
        """Handle API response, raising on errors."""
        if response.status_code >= 400:
            try:
                detail = response.json().get("detail", response.text)
            except Exception:
                detail = response.text
            raise APIError(response.status_code, detail)
        return response.json() if response.text else {}

    def health_check(self) -> bool:
        """Check if the server is healthy."""
        try:
            response = self.client.get(f"{self.base_url}/health")
            return response.status_code == 200
        except Exception:
            return False

    def get_stats(self) -> dict:
        """Get server statistics."""
        response = self.client.get(self._url("/query/stats"))
        return self._handle_response(response)

    # Product operations
    def list_products(self) -> list:
        """List all products, paginating through the full result set."""
        all_products = []
        offset = 0
        limit = 500
        while True:
            response = self.client.get(
                self._url("/products/"),
                params={"limit": limit, "offset": offset},
            )
            batch = self._handle_response(response)
            if not batch:
                break
            all_products.extend(batch)
            if len(batch) < limit:
                break
            offset += limit
        return all_products

    def get_product(self, name: str, version: str) -> dict:
        """Get a specific product."""
        response = self.client.get(self._url(f"/products/{name}/{version}"))
        return self._handle_response(response)

    def create_product(
        self,
        name: str,
        version: str,
        vendor: str = "Red Hat",
        cpe_vendor: str = "redhat",
        purl_namespace: str = "redhat",
        description: str = "",
    ) -> dict:
        """Create a product."""
        response = self.client.post(
            self._url("/products/"),
            json={
                "name": name,
                "version": version,
                "vendor": vendor,
                "cpe_vendor": cpe_vendor,
                "purl_namespace": purl_namespace,
                "description": description,
            },
        )
        return self._handle_response(response)

    # Scan operations
    def list_scans(self, product_name: Optional[str] = None) -> list:
        """List scans, optionally filtered by product."""
        params = {}
        if product_name:
            params["product_name"] = product_name
        response = self.client.get(self._url("/scans/"), params=params)
        return self._handle_response(response)

    def get_product_layers(self, product_name: str, product_version: str) -> Optional[dict]:
        """Get container layer chain for a product."""
        response = self.client.get(self._url(f"/products/{product_name}/{product_version}/layers"))
        if response.status_code == 404:
            return None
        return self._handle_response(response)

    def upload_scan(
        self,
        product_name: str,
        product_version: str,
        source_path: str,
        source_type: str,
        syft_version: str,
        original_sbom: dict,
        modified_sbom: dict,
        packages: list,
    ) -> dict:
        """
        Upload a complete scan.

        Args:
            product_name: Product name
            product_version: Product version
            source_path: Path that was scanned
            source_type: Type of source
            syft_version: Version of syft used
            original_sbom: Original syft-json SBOM dict
            modified_sbom: Modified SBOM dict
            packages: List of package dicts for indexing

        Returns:
            dict: Scan response
        """
        import tempfile
        import subprocess
        import os

        # Compress data to temp files for streaming upload
        console.print("[dim]Compressing data to temp files...[/dim]")

        with tempfile.TemporaryDirectory() as tmpdir:
            original_path = Path(tmpdir) / "original.json.gz"
            modified_path = Path(tmpdir) / "modified.json.gz"
            packages_path = Path(tmpdir) / "packages.json.gz"

            # Write compressed data to files
            with gzip.open(original_path, 'wt', encoding='utf-8') as f:
                json.dump(original_sbom, f)
            with gzip.open(modified_path, 'wt', encoding='utf-8') as f:
                json.dump(modified_sbom, f)
            with gzip.open(packages_path, 'wt', encoding='utf-8') as f:
                json.dump(packages, f)

            original_size = original_path.stat().st_size
            modified_size = modified_path.stat().st_size
            packages_size = packages_path.stat().st_size
            total_size = original_size + modified_size + packages_size

            console.print(
                f"[dim]Uploading scan: "
                f"original={original_size/1024/1024:.1f}MB, "
                f"modified={modified_size/1024/1024:.1f}MB, "
                f"index={packages_size/1024:.1f}KB "
                f"(total: {total_size/1024/1024:.1f}MB)[/dim]"
            )
            console.print("[dim]Sending to server via curl (this may take a while for large uploads)...[/dim]")

            # Use curl for large uploads - more reliable for very large multipart uploads
            curl_cmd = [
                "curl", "-s", "-S", "-X", "POST",
                self._url("/scans/upload"),
                "-F", f"product_name={product_name}",
                "-F", f"product_version={product_version}",
                "-F", f"source_path={source_path}",
                "-F", f"source_type={source_type}",
                "-F", f"syft_version={syft_version or ''}",
                "-F", f"original_sbom=@{original_path};type=application/gzip",
                "-F", f"modified_sbom=@{modified_path};type=application/gzip",
                "-F", f"packages_json=@{packages_path};type=application/gzip",
                "--connect-timeout", "30",
                "--max-time", "10800",  # 3 hours max for very large uploads
            ]

            # Pass API key header to curl if set
            if self._api_key:
                curl_cmd.extend(["-H", f"X-API-Key: {self._api_key}"])

            result = subprocess.run(curl_cmd, capture_output=True, text=True)

            if result.returncode != 0:
                raise APIError(500, f"Upload failed: {result.stderr}")

            try:
                response_data = json.loads(result.stdout)
                if "detail" in response_data:
                    raise APIError(400, response_data["detail"])
                return response_data
            except json.JSONDecodeError:
                raise APIError(500, f"Invalid response: {result.stdout}")

    def delete_scan(self, scan_id: int) -> None:
        """Delete a scan."""
        response = self.client.delete(self._url(f"/scans/{scan_id}"))
        if response.status_code >= 400:
            self._handle_response(response)

    def delete_product(self, product_name: str, product_version: str) -> None:
        """Delete a product and all its scans."""
        response = self.client.delete(self._url(f"/products/{product_name}/{product_version}"))
        if response.status_code >= 400:
            self._handle_response(response)

    def rename_product(
        self,
        product_name: str,
        product_version: str,
        new_name: Optional[str] = None,
        new_version: Optional[str] = None,
        new_description: Optional[str] = None,
    ) -> dict:
        """Rename or update a product."""
        body = {}
        if new_name is not None:
            body["name"] = new_name
        if new_version is not None:
            body["version"] = new_version
        if new_description is not None:
            body["description"] = new_description
        response = self.client.patch(
            self._url(f"/products/{product_name}/{product_version}"),
            json=body,
        )
        return self._handle_response(response)

    def list_tags(self, name: Optional[str] = None, limit: int = 100) -> list:
        """List all tags."""
        params = {"limit": limit}
        if name:
            params["name"] = name
        response = self.client.get(self._url("/tags/"), params=params)
        return self._handle_response(response)

    def rename_tag(self, tag_id: int, new_name: str) -> dict:
        """Rename a tag."""
        response = self.client.patch(
            self._url(f"/tags/{tag_id}"),
            json={"name": new_name},
        )
        return self._handle_response(response)

    def delete_tag(self, tag_id: int) -> None:
        """Delete a tag."""
        response = self.client.delete(self._url(f"/tags/{tag_id}"))
        if response.status_code >= 400:
            self._handle_response(response)

    # Job-based upload operations (for large scans)
    def upload_scan_async(
        self,
        product_name: str,
        product_version: str,
        source_path: str,
        source_type: str,
        syft_version: str,
        original_sbom: dict,
        modified_sbom: dict,
        packages: list,
        image_layers: Optional[List] = None,
        poll_interval: float = 5.0,
    ) -> dict:
        """
        Upload a scan using the async job-based flow.

        This method:
        1. Creates a job and gets presigned upload URLs
        2. Builds TSV files from packages
        3. Uploads SBOMs and TSV files to S3
        4. Starts the job
        5. Polls for completion

        This is memory-efficient for the server as it doesn't need to
        parse large JSON files.

        Args:
            product_name: Product name
            product_version: Product version
            source_path: Path that was scanned
            source_type: Type of source
            syft_version: Version of syft used
            original_sbom: Original syft-json SBOM dict
            modified_sbom: Modified SBOM dict
            packages: List of package dicts for indexing
            image_layers: Optional list of container layer info
            poll_interval: Seconds between status polls

        Returns:
            dict: Job response with scan_id when complete
        """
        import tempfile
        import subprocess

        # Count files
        total_files = sum(len(pkg.get("files", [])) for pkg in packages)
        total_packages = len(packages)

        console.print(f"[dim]Preparing upload: {total_packages} packages, {total_files} files[/dim]")

        # Step 1: Create job
        console.print("[dim]Creating import job...[/dim]")
        job_response = self.create_job(
            product_name=product_name,
            product_version=product_version,
            source_path=source_path,
            source_type=source_type,
            syft_version=syft_version,
            total_packages=total_packages,
            total_files=total_files,
            image_layers=image_layers,
        )
        job_id = job_response["job_id"]
        console.print(f"[dim]Job created: {job_id}[/dim]")

        # Step 2: Build TSV files
        console.print("[dim]Building TSV files...[/dim]")
        packages_tsv_gz, files_tsv_gz, pkg_count, file_count = build_tsv_files(packages)
        console.print(
            f"[dim]TSV built: packages={len(packages_tsv_gz)/1024:.1f}KB, "
            f"files={len(files_tsv_gz)/1024:.1f}KB[/dim]"
        )

        # Step 3: Upload files to presigned URLs
        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir = Path(tmpdir)

            # Write compressed SBOMs
            original_path = tmpdir / "original.json.gz"
            modified_path = tmpdir / "modified.json.gz"
            packages_path = tmpdir / "packages.tsv.gz"
            files_path = tmpdir / "files.tsv.gz"

            console.print("[dim]Compressing SBOMs...[/dim]")
            with gzip.open(original_path, 'wt', encoding='utf-8') as f:
                json.dump(original_sbom, f)
            with gzip.open(modified_path, 'wt', encoding='utf-8') as f:
                json.dump(modified_sbom, f)

            packages_path.write_bytes(packages_tsv_gz)
            if files_tsv_gz:
                files_path.write_bytes(files_tsv_gz)

            console.print("[dim]Uploading files to storage...[/dim]")

            # Upload each file to its presigned URL
            uploads = [
                ("original_sbom", original_path, job_response["original_sbom_url"]),
                ("modified_sbom", modified_path, job_response["modified_sbom_url"]),
                ("packages_tsv", packages_path, job_response["packages_tsv_url"]),
            ]
            if files_tsv_gz:
                uploads.append(("files_tsv", files_path, job_response["files_tsv_url"]))

            for name, path, url in uploads:
                size_kb = path.stat().st_size / 1024
                console.print(f"[dim]  Uploading {name} ({size_kb:.1f}KB)...[/dim]")
                self._upload_to_presigned_url(url, path)

        # Step 4: Start the job
        console.print("[dim]Starting import job...[/dim]")
        job_status = self.start_job(job_id)

        # Step 5: Poll for completion
        console.print("[dim]Processing in background, polling for status...[/dim]")
        return self.wait_for_job(job_id, poll_interval=poll_interval)

    def _upload_to_presigned_url(self, url: str, file_path: Path) -> None:
        """Upload a file to a presigned URL using curl."""
        import subprocess

        result = subprocess.run(
            [
                "curl", "-s", "-S", "-X", "PUT",
                "-T", str(file_path),
                "-H", "Content-Type: application/octet-stream",
                url,
            ],
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            raise APIError(500, f"Failed to upload to presigned URL: {result.stderr}")

    def create_job(
        self,
        product_name: str,
        product_version: str,
        source_path: str,
        source_type: str,
        syft_version: Optional[str],
        total_packages: int,
        total_files: int,
        image_layers: Optional[List] = None,
    ) -> dict:
        """Create a new import job."""
        payload = {
            "product_name": product_name,
            "product_version": product_version,
            "source_path": source_path,
            "source_type": source_type,
            "syft_version": syft_version or "",
            "total_packages": total_packages,
            "total_files": total_files,
        }
        if image_layers:
            payload["image_layers_json"] = json.dumps(image_layers)

        response = self.client.post(
            self._url("/jobs"),
            json=payload,
        )
        return self._handle_response(response)

    def start_job(self, job_id: str) -> dict:
        """Start processing an uploaded job."""
        response = self.client.post(self._url(f"/jobs/{job_id}/start"))
        return self._handle_response(response)

    def get_job(self, job_id: str) -> dict:
        """Get job status."""
        response = self.client.get(self._url(f"/jobs/{job_id}"))
        return self._handle_response(response)

    def list_jobs(
        self,
        status: Optional[str] = None,
        product_name: Optional[str] = None,
        limit: int = 50,
    ) -> dict:
        """List jobs with optional filtering."""
        params = {"limit": limit}
        if status:
            params["status"] = status
        if product_name:
            params["product_name"] = product_name
        response = self.client.get(self._url("/jobs"), params=params)
        return self._handle_response(response)

    def cancel_job(self, job_id: str) -> dict:
        """Cancel a pending job."""
        response = self.client.delete(self._url(f"/jobs/{job_id}"))
        return self._handle_response(response)

    def wait_for_job(
        self,
        job_id: str,
        poll_interval: float = 5.0,
        timeout: float = 3600.0,
    ) -> dict:
        """
        Wait for a job to complete.

        Args:
            job_id: Job ID to wait for
            poll_interval: Seconds between status checks
            timeout: Maximum time to wait in seconds

        Returns:
            dict: Final job status

        Raises:
            APIError: If job fails or times out
        """
        start_time = time.time()
        last_desc = ""

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
            transient=True,
        ) as progress:
            task = progress.add_task("Processing...", total=None)

            while True:
                elapsed = time.time() - start_time
                if elapsed > timeout:
                    raise APIError(408, f"Job timed out after {timeout}s")

                job = self.get_job(job_id)
                status = job["status"]
                
                # Format elapsed time
                mins, secs = divmod(int(elapsed), 60)
                if mins > 0:
                    elapsed_str = f"{mins}m {secs}s"
                else:
                    elapsed_str = f"{secs}s"

                # Build progress description
                total_pkgs = job["total_packages"]
                total_files = job["total_files"]
                proc_pkgs = job["processed_packages"]
                proc_files = job["processed_files"]
                
                if proc_pkgs == total_pkgs and proc_files == total_files and total_pkgs > 0:
                    # All done - show completion
                    desc = f"✓ Imported {total_pkgs:,} packages, {total_files:,} files ({elapsed_str})"
                elif proc_pkgs > 0 or proc_files > 0:
                    # Some progress - show it
                    if total_files > 0:
                        pct = (proc_files / total_files) * 100
                        desc = f"Importing: {proc_pkgs:,}/{total_pkgs:,} pkgs, {proc_files:,}/{total_files:,} files ({pct:.0f}%) [{elapsed_str}]"
                    else:
                        desc = f"Importing: {proc_pkgs:,}/{total_pkgs:,} packages [{elapsed_str}]"
                else:
                    # Still processing (bulk import in progress)
                    if total_files > 0:
                        desc = f"Importing {total_pkgs:,} packages, {total_files:,} files... [{elapsed_str}]"
                    else:
                        desc = f"Importing {total_pkgs:,} packages... [{elapsed_str}]"

                if desc != last_desc:
                    progress.update(task, description=desc)
                    last_desc = desc

                if status == "complete":
                    return job
                elif status == "failed":
                    raise APIError(500, f"Job failed: {job.get('error_message', 'Unknown error')}")

                time.sleep(poll_interval)

    # Query operations
    def search_packages(
        self,
        name: Optional[str] = None,
        pkg_version: Optional[str] = None,
        product_name: Optional[str] = None,
        product_version: Optional[str] = None,
        limit: int = 100,
    ) -> list:
        """Search for packages."""
        params = {"limit": limit}
        if name:
            params["name"] = name
        if pkg_version:
            params["pkg_version"] = pkg_version
        if product_name:
            params["product_name"] = product_name
        if product_version:
            params["product_version"] = product_version

        response = self.client.get(self._url("/query/packages"), params=params)
        return self._handle_response(response)

    def package_frequency(
        self,
        name: str,
        product_name: Optional[str] = None,
        product_version: Optional[str] = None,
        limit: int = 100,
    ) -> list:
        """Get version frequency for a package across SBOMs."""
        params = {"name": name, "limit": limit}
        if product_name:
            params["product_name"] = product_name
        if product_version:
            params["product_version"] = product_version
        response = self.client.get(self._url("/query/packages/frequency"), params=params)
        return self._handle_response(response)

    def search_files(
        self,
        path: Optional[str] = None,
        digest: Optional[str] = None,
        product_name: Optional[str] = None,
        product_version: Optional[str] = None,
        limit: int = 100,
    ) -> list:
        """Search for files."""
        params = {"limit": limit}
        if path:
            params["path"] = path
        if digest:
            params["digest"] = digest
        if product_name:
            params["product_name"] = product_name
        if product_version:
            params["product_version"] = product_version

        response = self.client.get(self._url("/query/files"), params=params)
        return self._handle_response(response)

    def trace_package(
        self,
        name: str,
        pkg_version: Optional[str] = None,
        limit: int = 200,
    ) -> dict:
        """Trace a package across the product stack."""
        params = {"name": name, "limit": limit}
        if pkg_version:
            params["pkg_version"] = pkg_version
        response = self.client.get(self._url("/query/trace"), params=params)
        return self._handle_response(response)

    def search_dependencies(
        self,
        package_name: Optional[str] = None,
        dependency_name: Optional[str] = None,
        dependency_type: Optional[str] = None,
        product_name: Optional[str] = None,
        product_version: Optional[str] = None,
        limit: int = 100,
    ) -> list:
        """Search RPM dependencies (requires/provides)."""
        params = {"limit": limit}
        if package_name:
            params["package_name"] = package_name
        if dependency_name:
            params["dependency_name"] = dependency_name
        if dependency_type:
            params["dependency_type"] = dependency_type
        if product_name:
            params["product_name"] = product_name
        if product_version:
            params["product_version"] = product_version

        response = self.client.get(self._url("/query/dependencies"), params=params)
        return self._handle_response(response)

    def list_relationships(self, limit: int = 100) -> list:
        """List component relationships."""
        params = {"limit": limit}
        response = self.client.get(self._url("/relationships/"), params=params)
        return self._handle_response(response)

    def list_all_packages(
        self,
        product_name: str,
        product_version: str,
    ) -> list:
        """List all packages for a product version."""
        response = self.client.get(
            self._url(f"/query/list/packages/{product_name}/{product_version}")
        )
        return self._handle_response(response)

    def list_all_files(
        self,
        product_name: str,
        product_version: str,
    ) -> list:
        """List all file paths for a product version."""
        response = self.client.get(
            self._url(f"/query/list/files/{product_name}/{product_version}")
        )
        return self._handle_response(response)

    def import_sbom(
        self,
        file_path: str,
        product_name: str,
        product_version: str,
        source_type: str = "sbom",
        description: Optional[str] = None,
        tags: Optional[list[str]] = None,
    ) -> dict:
        """Import an SBOM file (SPDX, CycloneDX, or syft-json)."""
        with open(file_path, "rb") as f:
            files = {"sbom": (os.path.basename(file_path), f)}
            data = {
                "product_name": product_name,
                "product_version": product_version,
                "source_type": source_type,
            }
            if description:
                data["description"] = description
            if tags:
                data["tags"] = ",".join(tags)
            response = self.client.post(
                self._url("/scans/import"),
                data=data,
                files=files,
                timeout=300.0,
            )
        return self._handle_response(response)

    def import_packages(
        self,
        file_path: str,
        product_name: str,
        product_version: str = "latest",
        source_type: str = "package-list",
    ) -> dict:
        """Import a package list (JSON array or CSV) without a full SBOM."""
        with open(file_path, "rb") as f:
            files = {"packages": (os.path.basename(file_path), f)}
            data = {
                "product_name": product_name,
                "product_version": product_version,
                "source_type": source_type,
            }
            response = self.client.post(
                self._url("/scans/import-packages"),
                data=data,
                files=files,
                timeout=300.0,
            )
        return self._handle_response(response)

    # ========================================================================
    # System operations (infrastructure mode)
    # ========================================================================

    def list_systems(self, tag: Optional[str] = None) -> list:
        """List all systems."""
        params = {}
        if tag:
            params["tag"] = tag
        response = self.client.get(self._url("/systems/"), params=params)
        return self._handle_response(response)

    def get_system(self, hostname: str) -> dict:
        """Get a specific system."""
        response = self.client.get(self._url(f"/systems/{hostname}"))
        return self._handle_response(response)

    def search_system_packages(
        self,
        name: Optional[str] = None,
        hostname: Optional[str] = None,
        tag: Optional[str] = None,
        limit: int = 100,
    ) -> list:
        """Search for packages across systems."""
        params = {"limit": limit}
        if name:
            params["name"] = name
        if hostname:
            params["hostname"] = hostname
        if tag:
            params["tag"] = tag

        response = self.client.get(self._url("/query/systems/packages"), params=params)
        return self._handle_response(response)

    def search_system_files(
        self,
        path: Optional[str] = None,
        digest: Optional[str] = None,
        hostname: Optional[str] = None,
        tag: Optional[str] = None,
        limit: int = 100,
    ) -> list:
        """Search for files across systems."""
        params = {"limit": limit}
        if path:
            params["path"] = path
        if digest:
            params["digest"] = digest
        if hostname:
            params["hostname"] = hostname
        if tag:
            params["tag"] = tag

        response = self.client.get(self._url("/query/systems/files"), params=params)
        return self._handle_response(response)

    def list_system_packages(self, hostname: str) -> list:
        """List all packages for a system."""
        response = self.client.get(
            self._url(f"/query/systems/list/packages/{hostname}")
        )
        return self._handle_response(response)

    def list_system_files(self, hostname: str) -> list:
        """List all file paths for a system."""
        response = self.client.get(
            self._url(f"/query/systems/list/files/{hostname}")
        )
        return self._handle_response(response)

    def upload_system_scan_async(
        self,
        hostname: str,
        ip_address: Optional[str],
        os_name: Optional[str],
        os_version: Optional[str],
        architecture: Optional[str],
        tag: Optional[str],
        syft_version: str,
        original_sbom: dict,
        modified_sbom: dict,
        packages: list,
        poll_interval: float = 5.0,
    ) -> dict:
        """
        Upload a system scan using the async job-based flow.

        This method:
        1. Creates a job and gets presigned upload URLs
        2. Builds TSV files from packages
        3. Uploads SBOMs and TSV files to S3
        4. Starts the job
        5. Polls for completion

        Args:
            hostname: System hostname
            ip_address: System IP address
            os_name: Operating system name
            os_version: Operating system version
            architecture: System architecture
            tag: Optional tag for grouping
            syft_version: Version of syft used
            original_sbom: Original syft-json SBOM dict
            modified_sbom: Modified SBOM dict
            packages: List of package dicts for indexing
            poll_interval: Seconds between status polls

        Returns:
            dict: Job response with scan_id when complete
        """
        import tempfile

        # Count files
        total_files = sum(len(pkg.get("files", [])) for pkg in packages)
        total_packages = len(packages)

        console.print(f"[dim]Preparing upload: {total_packages} packages, {total_files} files[/dim]")

        # Step 1: Create job for system
        console.print("[dim]Creating system import job...[/dim]")
        job_response = self.create_system_job(
            hostname=hostname,
            ip_address=ip_address,
            os_name=os_name,
            os_version=os_version,
            architecture=architecture,
            tag=tag,
            syft_version=syft_version,
            total_packages=total_packages,
            total_files=total_files,
        )
        job_id = job_response["job_id"]
        console.print(f"[dim]Job created: {job_id}[/dim]")

        # Step 2: Build TSV files
        console.print("[dim]Building TSV files...[/dim]")
        packages_tsv_gz, files_tsv_gz, pkg_count, file_count = build_tsv_files(packages)
        console.print(
            f"[dim]TSV built: packages={len(packages_tsv_gz)/1024:.1f}KB, "
            f"files={len(files_tsv_gz)/1024:.1f}KB[/dim]"
        )

        # Step 3: Upload files to presigned URLs
        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir = Path(tmpdir)

            # Write compressed SBOMs
            original_path = tmpdir / "original.json.gz"
            modified_path = tmpdir / "modified.json.gz"
            packages_path = tmpdir / "packages.tsv.gz"
            files_path = tmpdir / "files.tsv.gz"

            console.print("[dim]Compressing SBOMs...[/dim]")
            with gzip.open(original_path, 'wt', encoding='utf-8') as f:
                json.dump(original_sbom, f)
            with gzip.open(modified_path, 'wt', encoding='utf-8') as f:
                json.dump(modified_sbom, f)

            packages_path.write_bytes(packages_tsv_gz)
            if files_tsv_gz:
                files_path.write_bytes(files_tsv_gz)

            console.print("[dim]Uploading files to storage...[/dim]")

            # Upload each file to its presigned URL
            uploads = [
                ("original_sbom", original_path, job_response["original_sbom_url"]),
                ("modified_sbom", modified_path, job_response["modified_sbom_url"]),
                ("packages_tsv", packages_path, job_response["packages_tsv_url"]),
            ]
            if files_tsv_gz:
                uploads.append(("files_tsv", files_path, job_response["files_tsv_url"]))

            for name, path, url in uploads:
                size_kb = path.stat().st_size / 1024
                console.print(f"[dim]  Uploading {name} ({size_kb:.1f}KB)...[/dim]")
                self._upload_to_presigned_url(url, path)

        # Step 4: Start the job
        console.print("[dim]Starting import job...[/dim]")
        job_status = self.start_job(job_id)

        # Step 5: Poll for completion
        console.print("[dim]Processing in background, polling for status...[/dim]")
        return self.wait_for_job(job_id, poll_interval=poll_interval)

    def create_system_job(
        self,
        hostname: str,
        ip_address: Optional[str],
        os_name: Optional[str],
        os_version: Optional[str],
        architecture: Optional[str],
        tag: Optional[str],
        syft_version: Optional[str],
        total_packages: int,
        total_files: int,
    ) -> dict:
        """Create a new import job for a system scan."""
        response = self.client.post(
            self._url("/jobs/system"),
            json={
                "hostname": hostname,
                "ip_address": ip_address,
                "os_name": os_name,
                "os_version": os_version,
                "architecture": architecture,
                "tag": tag,
                "syft_version": syft_version or "",
                "total_packages": total_packages,
                "total_files": total_files,
            },
        )
        return self._handle_response(response)

    # Export operations
    def get_sbom(
        self,
        product_name: str,
        product_version: str,
        format: str = "syft-json",
    ) -> bytes:
        """
        Download an SBOM.

        Args:
            product_name: Product name
            product_version: Product version
            format: Output format (syft-json, original)

        Returns:
            bytes: Compressed SBOM data
        """
        response = self.client.get(
            self._url(f"/export/{product_name}/{product_version}"),
            params={"format": format},
        )
        if response.status_code >= 400:
            self._handle_response(response)
        return response.content

    def get_sbom_url(
        self,
        product_name: str,
        product_version: str,
        expires_in: int = 3600,
    ) -> str:
        """Get a presigned URL for downloading an SBOM."""
        response = self.client.get(
            self._url(f"/export/{product_name}/{product_version}/url"),
            params={"expires_in": expires_in},
        )
        data = self._handle_response(response)
        return data["download_url"]

    def close(self):
        """Close the client."""
        self.client.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()


def get_client(server_url: Optional[str] = None) -> SyfterClient:
    """
    Get a client instance.

    Args:
        server_url: Server URL (defaults to SYFTER_SERVER env var or http://localhost:8000)

    Returns:
        SyfterClient: Client instance
    """
    url = server_url or os.getenv("SYFTER_SERVER", "http://localhost:8000")
    return SyfterClient(url)
