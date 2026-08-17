"""
CLI interface for Syfter.

Supports two modes:
- Server mode: Uses API server (set SYFTER_SERVER env var)
- Local mode: Direct SQLite access (for development/testing)
"""

import gzip
import json
import os
import sys
from pathlib import Path
from typing import Optional

import click
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box

from . import __version__
from .models import Product
from .scanner import (
    scan_directory,
    scan_container,
    scan_target,
    scan_localhost,
    scan_remote_host,
    mirror_and_scan_url,
    get_source_type,
    get_host_info,
    get_remote_host_info,
    get_container_layer_info,
    get_package_source_images,
    check_syft_installed,
    cleanup_stale_temp_dirs,
    SyftNotFoundError,
    ScanError,
)
from .manipulator import (
    modify_sbom,
    extract_packages,
    extract_image_layers,
    build_layer_map,
    parse_containerfile,
    map_layers_to_images,
)
from .exporter import (
    export_to_spdx_json,
    export_to_spdx_tv,
    export_to_cyclonedx_json,
    export_to_cyclonedx_xml,
    batch_export,
    ExportError,
)

console = Console()

# Maximum decompressed size to prevent zip bombs (4GB for large distros like RHEL)
_MAX_DECOMPRESSED_SIZE = 4 * 1024 * 1024 * 1024


def _safe_gzip_decompress(data: bytes, max_size: int = _MAX_DECOMPRESSED_SIZE) -> bytes:
    """
    Safely decompress gzip data with size limit to prevent decompression bombs.
    """
    import io
    decompressor = gzip.GzipFile(fileobj=io.BytesIO(data))
    chunks = []
    total_size = 0

    while True:
        chunk = decompressor.read(1024 * 1024)
        if not chunk:
            break
        total_size += len(chunk)
        if total_size > max_size:
            raise ValueError(f"Decompressed data ({total_size // (1024*1024)}MB so far) exceeds {max_size // (1024*1024*1024)}GB limit")
        chunks.append(chunk)

    return b''.join(chunks)


def get_server_url() -> Optional[str]:
    """Get the server URL from environment or None for local mode."""
    return os.getenv("SYFTER_SERVER")


def is_server_mode() -> bool:
    """Check if running in server mode."""
    return get_server_url() is not None


class AliasedGroup(click.Group):
    _aliases = {"query": "search", "list": "show"}
    _removed = {"job", "jobs"}

    def get_command(self, ctx, cmd_name):
        if cmd_name in self._removed:
            click.echo(f"Error: '{cmd_name}' has been removed.", err=True)
            return None
        if cmd_name in self._aliases:
            click.echo(
                f"Warning: '{cmd_name}' is deprecated, use '{self._aliases[cmd_name]}' instead",
                err=True,
            )
            cmd_name = self._aliases[cmd_name]
        return super().get_command(ctx, cmd_name)


@click.group(cls=AliasedGroup)
@click.version_option(version=__version__)
@click.option(
    "--server",
    "server_url",
    envvar="SYFTER_SERVER",
    help="API server URL (default: local mode)",
)
@click.option(
    "--local",
    "force_local",
    is_flag=True,
    help="Force local mode even if SYFTER_SERVER is set",
)
@click.pass_context
def main(ctx, server_url: Optional[str], force_local: bool):
    """
    Syfter: SBOM generation and management tool.

    Scan RPM directories, containers, and other artifacts to generate SBOMs,
    enrich them with product metadata, and query across all your products.

    Modes:
      - Server mode: Set SYFTER_SERVER=http://server:8000 or use --server
      - Local mode: Uses local SQLite database (default, or use --local)
    """
    ctx.ensure_object(dict)
    ctx.obj["server_url"] = None if force_local else server_url
    ctx.obj["local_mode"] = force_local or server_url is None

    # Clean up any stale temp directories from previous runs
    cleanup_stale_temp_dirs()


@main.command()
@click.argument("target", type=str)
@click.option("-p", "--product", required=True, help="Product name (e.g., 'rhel')")
@click.option("-v", "--version", "product_version", required=True, help="Product version (e.g., '10.0')")
@click.option("--vendor", default="Red Hat", help="Vendor name")
@click.option("--cpe-vendor", default="redhat", help="CPE vendor string")
@click.option("--purl-namespace", default="redhat", help="PURL namespace")
@click.option("--description", default="", help="Product description")
@click.option("-o", "--output", type=click.Path(path_type=Path), help="Write SBOM to file")
@click.option("--no-store", is_flag=True, help="Don't store (just output)")
@click.option("-s", "--source", type=click.Choice(["auto", "podman", "docker", "registry", "skopeo"]), default="auto")
@click.option("--pull-first", is_flag=True, help="Pull image with skopeo first")
@click.option("--arch", type=click.Choice(["amd64", "arm64", "ppc64le", "s390x"]), default=None)
@click.option("-q", "--quiet", is_flag=True, help="Suppress progress output")
@click.option("--skip-files", is_flag=True, help="Skip file indexing (faster, uses less memory)")
@click.option("--include-debug", is_flag=True, help="Include debuginfo/debugsource packages (excluded by default)")
@click.option("--containerfile", type=click.Path(exists=True), help="Path to Containerfile to extract base image chain")
@click.option("--base-image", multiple=True, help="Base image reference(s) for layer mapping (repeatable)")
@click.option("--remote", is_flag=True, help="Run scan server-side (server mirrors and scans the URL)")
@click.pass_context
def scan(
    ctx,
    target: str,
    product: str,
    product_version: str,
    vendor: str,
    cpe_vendor: str,
    purl_namespace: str,
    description: str,
    output: Optional[Path],
    no_store: bool,
    source: str,
    pull_first: bool,
    arch: Optional[str],
    quiet: bool,
    skip_files: bool,
    include_debug: bool,
    containerfile: Optional[str],
    base_image: tuple,
    remote: bool,
):
    """Scan a target and store the SBOM with product metadata."""
    # Handle server-side remote scanning
    if remote:
        if ctx.obj["local_mode"]:
            console.print("[red]Error: --remote requires server mode (set SYFTER_SERVER)[/red]")
            sys.exit(1)
        if not target.startswith(("http://", "https://")):
            console.print("[red]Error: --remote requires an HTTP/HTTPS URL as the target[/red]")
            sys.exit(1)
        _remote_scan(ctx, target, product, product_version, description, skip_files, not include_debug)
        return

    try:
        check_syft_installed()
    except SyftNotFoundError as e:
        console.print(f"[red]Error: {e}[/red]")
        sys.exit(1)

    prod = Product(
        name=product,
        version=product_version,
        vendor=vendor,
        cpe_vendor=cpe_vendor,
        purl_namespace=purl_namespace,
        description=description,
    )

    console.print(Panel(
        f"[bold]Scanning:[/bold] {target}\n"
        f"[bold]Product:[/bold] {prod.full_name}\n"
        f"[bold]Mode:[/bold] {'Server' if not ctx.obj['local_mode'] else 'Local'}",
        title="Syfter Scan",
        box=box.ROUNDED,
    ))

    source_type = get_source_type(target)
    console.print(f"[dim]Source type: {source_type}[/dim]")

    try:
        exclude_debug = not include_debug
        if source_type == "url":
            original_sbom, syft_version = mirror_and_scan_url(
                target, show_progress=not quiet, name=prod.full_name, version=product_version,
                exclude_debug=exclude_debug
            )
        elif source_type == "directory":
            path = Path(target.replace("dir:", ""))
            original_sbom, syft_version = scan_directory(
                path, show_progress=not quiet, name=prod.full_name, version=product_version,
                exclude_debug=exclude_debug
            )
        elif source_type == "container":
            container_source = None if source == "auto" else source
            original_sbom, syft_version = scan_container(
                target, source=container_source, pull_first=pull_first,
                arch=arch, show_progress=not quiet, name=prod.full_name, version=product_version,
                exclude_debug=exclude_debug
            )
        else:
            original_sbom, syft_version = scan_target(
                target, show_progress=not quiet, name=prod.full_name, version=product_version,
                exclude_debug=exclude_debug
            )
    except ScanError as e:
        console.print(f"[red]Scan failed: {e}[/red]")
        sys.exit(1)

    modified_sbom = modify_sbom(original_sbom, prod, exclude_debug=not include_debug)

    # Extract layer information for container scans
    layer_map = None
    image_layers = []
    if source_type == "container":
        image_layers = extract_image_layers(modified_sbom)
        if image_layers:
            console.print(f"[dim]Found {len(image_layers)} container layers[/dim]")
            layer_map = build_layer_map(image_layers)

            # Get source image mapping and complete layer chain from container metadata
            clean_target = target
            for prefix in ["docker:", "podman:", "registry:", "oci-dir:", "oci-archive:"]:
                if clean_target.startswith(prefix):
                    clean_target = clean_target[len(prefix):]
                    break

            source_image_map, layer_chain = get_container_layer_info(clean_target, arch=arch or "amd64")

            # Store the complete layer chain for the 'layers' command
            if layer_chain:
                # Update image_layers with the full chain info
                image_layers = layer_chain

            # Merge source image info into layer_map
            if source_image_map:
                for layer_id, layer_info in layer_map.items():
                    if layer_id in source_image_map:
                        layer_info["source_image"] = source_image_map[layer_id]

            # If user provided Containerfile, use that as override
            if containerfile:
                parsed_images = parse_containerfile(containerfile)
                if parsed_images:
                    console.print(f"[dim]Parsed FROM chain from Containerfile: {' -> '.join(parsed_images)}[/dim]")

    packages = extract_packages(modified_sbom, skip_files=skip_files, layer_map=layer_map)

    # Count packages with layer info
    if layer_map:
        pkgs_with_layers = sum(1 for p in packages if p.get("layer_id"))
        console.print(f"[dim]Packages with layer info: {pkgs_with_layers}/{len(packages)}[/dim]")

        # For RPM-based containers, determine true package provenance by scanning base images
        # This is necessary because RPM packages all appear in the top layer (where rpmdb lives)
        if pkgs_with_layers > 0 and not containerfile:
            # Try to determine package sources by scanning base images
            clean_target = target
            for prefix in ["docker:", "podman:", "registry:", "oci-dir:", "oci-archive:"]:
                if clean_target.startswith(prefix):
                    clean_target = clean_target[len(prefix):]
                    break

            pkg_sources, verified_chain = get_package_source_images(clean_target, packages, arch=arch or "amd64")
            if pkg_sources:
                # Update packages with source image info
                for pkg in packages:
                    pkg_name = pkg.get("name")
                    if pkg_name and pkg_name in pkg_sources:
                        source_info = pkg_sources[pkg_name]
                        pkg["source_image"] = source_info.get("name")
                        pkg["source_image_ref"] = source_info.get("full_reference")

                sources_filled = sum(1 for p in packages if p.get("source_image"))
                console.print(f"[green]Packages with source image: {sources_filled}/{len(packages)}[/green]")

            # Update image_layers with verified chain info
            if verified_chain:
                # Rebuild image_layers with accurate info from verified chain
                target_meta = verified_chain[-1] if verified_chain else {}
                target_layers = target_meta.get("layers", [])

                # Map each layer to the image that introduced it
                # Layer at index N was introduced by the first image in the chain
                # (sorted by layer count) whose layer count is > N
                new_image_layers = []
                for idx, layer_digest in enumerate(target_layers):
                    if layer_digest.startswith("sha256:"):
                        layer_id = layer_digest[7:20]
                    else:
                        layer_id = layer_digest[:13]

                    # Find which image introduced this layer
                    # It's the first image in the chain whose layer count > idx
                    source_img = None
                    for img_info in verified_chain:
                        img_layer_count = img_info.get("layer_count", 0)
                        if img_layer_count > idx:
                            source_img = img_info
                            break

                    if source_img:
                        new_image_layers.append({
                            "layer_index": idx,
                            "layer_id": layer_id,
                            "full_digest": layer_digest,
                            "source_image": source_img.get("name"),
                            "source_version": source_img.get("version"),
                            "source_release": source_img.get("release"),
                            "image_reference": source_img.get("full_reference"),
                        })

                if new_image_layers:
                    image_layers = new_image_layers

    if skip_files:
        console.print("[yellow]Note: File indexing skipped (--skip-files). File search won't work for this scan.[/yellow]")

    if output:
        output.write_text(json.dumps(modified_sbom, indent=2))
        console.print(f"[green]Wrote SBOM to {output}[/green]")

    if no_store:
        console.print("[yellow]Skipped storage (--no-store)[/yellow]")
        return

    if ctx.obj["local_mode"]:
        _store_local(ctx, prod, target, source_type, syft_version, original_sbom, modified_sbom, packages, image_layers)
    else:
        _store_server(ctx, prod, target, source_type, syft_version, original_sbom, modified_sbom, packages, image_layers)


def _store_local(ctx, prod, target, source_type, syft_version, original_sbom, modified_sbom, packages, image_layers=None):
    """Store scan using local SQLite storage."""
    from .storage import Storage

    storage = Storage()
    product_id = storage.get_or_create_product(prod)
    scan_id = storage.store_scan(
        product_id=product_id,
        source_path=target,
        source_type=source_type,
        syft_version=syft_version,
        original_sbom=original_sbom,
        modified_sbom=modified_sbom,
        packages=packages,
        image_layers=image_layers,
    )
    console.print(f"[green]✓ Scan #{scan_id} stored locally[/green]")


def _store_server(ctx, prod, target, source_type, syft_version, original_sbom, modified_sbom, packages, image_layers=None):
    """Store scan using API server with direct upload."""
    from .client import SyfterClient, APIError
    import httpx

    server_url = ctx.obj["server_url"]
    try:
        with SyfterClient(server_url) as client:
            result = client.upload_scan(
                product_name=prod.name,
                product_version=prod.version,
                source_path=target,
                source_type=source_type,
                syft_version=syft_version,
                original_sbom=original_sbom,
                modified_sbom=modified_sbom,
                packages=packages,
            )
            scan_id = result.get("scan_id", "unknown")
            console.print(f"[green]Scan #{scan_id} uploaded to server[/green]")
    except httpx.ConnectError:
        console.print(f"[red]Error: Cannot connect to server at {server_url}[/red]")
        console.print("[dim]Is the server running? Check with: curl {}/health[/dim]".format(server_url))
        sys.exit(1)
    except APIError as e:
        console.print(f"[red]Upload failed: {e}[/red]")
        sys.exit(1)


def _remote_scan(ctx, url, product_name, product_version, description, skip_files, exclude_debug):
    """Trigger a server-side remote scan via the API."""
    from .client import SyfterClient, APIError
    import httpx

    server_url = ctx.obj["server_url"]

    console.print(Panel(
        f"[bold]Remote URL:[/bold] {url}\n"
        f"[bold]Product:[/bold] {product_name}-{product_version}\n"
        f"[bold]Mode:[/bold] Server-side (remote)",
        title="Syfter Remote Scan",
        box=box.ROUNDED,
    ))

    try:
        with SyfterClient(server_url) as client:
            response = client.client.post(
                client._url("/jobs/remote"),
                json={
                    "url": url,
                    "product_name": product_name,
                    "product_version": product_version,
                    "description": description,
                    "skip_files": skip_files,
                    "exclude_debug": exclude_debug,
                },
            )

            if response.status_code >= 400:
                try:
                    detail = response.json().get("detail", response.text)
                except Exception:
                    detail = response.text
                console.print(f"[red]Error: {detail}[/red]")
                sys.exit(1)

            job = response.json()
            job_id = job["id"]
            console.print(f"[green]Remote scan job created: {job_id}[/green]")
            console.print("[dim]The server is mirroring, scanning, and importing. Polling for status...[/dim]")

            result = client.wait_for_job(job_id, poll_interval=10.0)
            scan_id = result.get("scan_id", "unknown")
            console.print(f"[green]Remote scan complete! Scan #{scan_id} (job: {job_id})[/green]")

    except httpx.ConnectError:
        console.print(f"[red]Error: Cannot connect to server at {server_url}[/red]")
        sys.exit(1)
    except APIError as e:
        console.print(f"[red]Remote scan failed: {e}[/red]")
        sys.exit(1)


@main.command("search")
@click.option("-n", "--name", help="Package name pattern (use %% as wildcard)")
@click.option("--pkg-version", help="Package version pattern (use %% as wildcard)")
@click.option("-f", "--file", "file_path", help="File path pattern")
@click.option("-d", "--digest", help="File digest (exact match)")
@click.option("-p", "--product", help="Filter by product name")
@click.option("-v", "--version", "product_version", help="Filter by product version")
@click.option("--limit", type=int, default=50, help="Maximum results")
@click.option("--json", "output_json", is_flag=True, help="Output as JSON")
@click.option("--cross-product", is_flag=True, help="Trace package across the full product stack (JSON output)")
@click.pass_context
def query(ctx, name, pkg_version, file_path, digest, product, product_version, limit, output_json, cross_product):
    """Search packages and files across all products."""
    if cross_product:
        if not name:
            console.print("[red]Error: --cross-product requires --name[/red]")
            sys.exit(1)
        if ctx.obj["local_mode"]:
            console.print("[red]Error: --cross-product requires server mode[/red]")
            sys.exit(1)
        from .client import SyfterClient, APIError
        import httpx
        try:
            with SyfterClient(ctx.obj["server_url"]) as client:
                result = client.trace_package(name=name, pkg_version=pkg_version, limit=limit)
                click.echo(json.dumps(result, indent=2))
        except httpx.ConnectError:
            console.print(f"[red]Error: Cannot connect to server at {ctx.obj['server_url']}[/red]")
            sys.exit(1)
        except APIError as e:
            console.print(f"[red]Cross-product search failed: {e}[/red]")
            sys.exit(1)
        return

    if ctx.obj["local_mode"]:
        _query_local(name, pkg_version, file_path, digest, product, product_version, limit, output_json)
    else:
        _query_server(ctx, name, pkg_version, file_path, digest, product, product_version, limit, output_json)


def _query_local(name, pkg_version, file_path, digest, product, product_version, limit, output_json):
    """Query using local SQLite storage."""
    from .storage import Storage

    storage = Storage()

    if file_path or digest:
        results = storage.search_files(
            path_pattern=file_path, digest=digest,
            product_name=product, product_version=product_version, limit=limit
        )
        if output_json:
            click.echo(json.dumps(results, indent=2))
            return
        if not results:
            console.print("[yellow]No files found[/yellow]")
            return
        table = Table(title="File Search Results", box=box.SIMPLE)
        table.add_column("Path", style="cyan")
        table.add_column("Package", style="green")
        table.add_column("Product", style="magenta")
        # Only show source_image column if any result has it
        has_source_image = any(row.get('source_image') for row in results)
        if has_source_image:
            table.add_column("Source Image", style="yellow")
        for row in results:
            pkg_info = row['package_name']
            if row.get('package_version'):
                pkg_info += f"-{row['package_version']}"
            if has_source_image:
                table.add_row(row["path"], pkg_info, f"{row['product_name']}-{row['product_version']}",
                            row.get('source_image') or "")
            else:
                table.add_row(row["path"], pkg_info, f"{row['product_name']}-{row['product_version']}")
        console.print(table)

    elif name:
        results = storage.search_packages(
            name_pattern=name, pkg_version=pkg_version,
            product_name=product, product_version=product_version, limit=limit
        )
        if output_json:
            click.echo(json.dumps(results, indent=2))
            return
        if not results:
            console.print("[yellow]No packages found[/yellow]")
            return
        table = Table(title="Package Search Results", box=box.SIMPLE)
        table.add_column("Name", style="cyan")
        table.add_column("Version", style="green")
        table.add_column("Product", style="magenta")
        # Only show source_image column if any result has it
        has_source_image = any(row.get('source_image') for row in results)
        if has_source_image:
            table.add_column("Source Image", style="yellow")
        for row in results:
            if has_source_image:
                table.add_row(row["name"], row["version"] or "", f"{row['product_name']}-{row['product_version']}",
                            row.get('source_image') or "")
            else:
                table.add_row(row["name"], row["version"] or "", f"{row['product_name']}-{row['product_version']}")
        console.print(table)
    else:
        console.print("[yellow]Please specify --name, --file, or --digest[/yellow]")


def _query_server(ctx, name, pkg_version, file_path, digest, product, product_version, limit, output_json):
    """Query using API server."""
    from .client import SyfterClient, APIError
    import httpx

    server_url = ctx.obj["server_url"]
    try:
        with SyfterClient(server_url) as client:
            if file_path or digest:
                results = client.search_files(
                    path=file_path, digest=digest,
                    product_name=product, product_version=product_version, limit=limit
                )
                if output_json:
                    click.echo(json.dumps(results, indent=2))
                    return
                if not results:
                    console.print("[yellow]No files found[/yellow]")
                    return
                table = Table(title="File Search Results", box=box.SIMPLE)
                table.add_column("Path", style="cyan")
                table.add_column("Package", style="green")
                table.add_column("Product", style="magenta")
                # Only show source_image column if any result has it
                has_source_image = any(row.get('source_image') for row in results)
                if has_source_image:
                    table.add_column("Source Image", style="yellow")
                for row in results:
                    pkg_info = row['package_name']
                    if row.get('package_version'):
                        pkg_info += f"-{row['package_version']}"
                    if has_source_image:
                        table.add_row(row["path"], pkg_info, f"{row['product_name']}-{row['product_version']}",
                                    row.get('source_image') or "")
                    else:
                        table.add_row(row["path"], pkg_info, f"{row['product_name']}-{row['product_version']}")
                console.print(table)

            elif name:
                results = client.search_packages(
                    name=name, pkg_version=pkg_version,
                    product_name=product, product_version=product_version, limit=limit
                )
                if output_json:
                    click.echo(json.dumps(results, indent=2))
                    return
                if not results:
                    console.print("[yellow]No packages found[/yellow]")
                    return
                table = Table(title="Package Search Results", box=box.SIMPLE)
                table.add_column("Name", style="cyan")
                table.add_column("Version", style="green")
                table.add_column("Product", style="magenta")
                # Only show source_image column if any result has it
                has_source_image = any(row.get('source_image') for row in results)
                if has_source_image:
                    table.add_column("Source Image", style="yellow")
                for row in results:
                    if has_source_image:
                        table.add_row(row["name"], row["version"] or "", f"{row['product_name']}-{row['product_version']}",
                                    row.get('source_image') or "")
                    else:
                        table.add_row(row["name"], row["version"] or "", f"{row['product_name']}-{row['product_version']}")
                console.print(table)
            else:
                console.print("[yellow]Please specify --name, --file, or --digest[/yellow]")
    except httpx.ConnectError:
        console.print(f"[red]Error: Cannot connect to server at {server_url}[/red]")
        console.print("[dim]Is the server running? Check with: curl {}/health[/dim]".format(server_url))
        sys.exit(1)
    except APIError as e:
        console.print(f"[red]Query failed: {e}[/red]")
        sys.exit(1)


@main.command("frequency")
@click.option("-n", "--name", required=True, help="Package name (exact match or %% wildcard)")
@click.option("-p", "--product", help="Filter by product name (%% wildcard)")
@click.option("-v", "--version", "product_version", help="Filter by product version (%% wildcard)")
@click.option("--limit", type=int, default=100, help="Maximum versions to return")
@click.option("--json", "output_json", is_flag=True, help="Output as JSON")
@click.pass_context
def frequency(ctx, name, product, product_version, limit, output_json):
    """Show version frequency for a package across SBOMs.

    Counts how many SBOMs contain each version of a package, sorted by
    frequency. Useful for identifying the most common versions in use.
    """
    if ctx.obj["local_mode"]:
        console.print("[red]Error: frequency requires server mode[/red]")
        sys.exit(1)

    from .client import SyfterClient, APIError
    import httpx

    try:
        with SyfterClient(ctx.obj["server_url"]) as client:
            results = client.package_frequency(
                name=name, product_name=product,
                product_version=product_version, limit=limit,
            )
            if output_json:
                click.echo(json.dumps(results, indent=2))
                return
            if not results:
                console.print("[yellow]No packages found[/yellow]")
                return
            table = Table(title=f"Version Frequency: {name}", box=box.SIMPLE)
            table.add_column("Version", style="cyan")
            table.add_column("SBOMs", style="green", justify="right")
            table.add_column("Products", style="magenta")
            for row in results:
                products_str = ", ".join(row["products"][:5])
                if len(row["products"]) > 5:
                    products_str += f" (+{len(row['products']) - 5} more)"
                table.add_row(
                    row["version"] or "(empty)",
                    str(row["sbom_count"]),
                    products_str,
                )
            console.print(table)
    except httpx.ConnectError:
        console.print(f"[red]Error: Cannot connect to server at {ctx.obj['server_url']}[/red]")
        sys.exit(1)
    except APIError as e:
        console.print(f"[red]Frequency query failed: {e}[/red]")
        sys.exit(1)


@main.command("import")
@click.argument("file_path", type=click.Path(exists=True))
@click.option("-p", "--product", required=True, help="Product name")
@click.option("-v", "--version", "product_version", required=True, help="Product version")
@click.option("--description", help="Description for this SBOM")
@click.option("--source-type", default="sbom", help="Source type (default: sbom)")
@click.option("--tag", "tags", multiple=True, help="Tag to apply (repeatable)")
@click.option("--json", "output_json", is_flag=True, help="Output response as JSON")
@click.pass_context
def import_sbom(ctx, file_path, product, product_version, description, source_type, tags, output_json):
    """Import an SBOM file (SPDX, CycloneDX, or syft-json).

    Auto-detects format and indexes all packages. The original SBOM is
    stored as-is in object storage.

    Example: syfter import customer-sbom.spdx.json -p acme-app -v 2.1
    """
    if ctx.obj["local_mode"]:
        console.print("[red]Error: import requires server mode[/red]")
        sys.exit(1)

    from .client import SyfterClient, APIError
    import httpx

    try:
        with SyfterClient(ctx.obj["server_url"]) as client:
            result = client.import_sbom(
                file_path=file_path,
                product_name=product,
                product_version=product_version,
                source_type=source_type,
                description=description,
                tags=list(tags) if tags else None,
            )
            if output_json:
                click.echo(json.dumps(result, indent=2))
                return
            console.print(f"[green]Imported {result['package_count']} packages[/green]")
            console.print(f"  Format:  {result['sbom_format']}")
            console.print(f"  Product: {result['product_name']}-{result['product_version']}")
            console.print(f"  Scan ID: {result['id']}")
            if result.get("tags"):
                console.print(f"  Tags:    {', '.join(result['tags'])}")
    except httpx.ConnectError:
        console.print(f"[red]Error: Cannot connect to server at {ctx.obj['server_url']}[/red]")
        sys.exit(1)
    except APIError as e:
        console.print(f"[red]Import failed: {e}[/red]")
        sys.exit(1)


def _get_format_extension(output_format: str) -> str:
    """Get the file extension for a given format."""
    extensions = {
        "syft-json": ".syft.json",
        "spdx-json": ".spdx.json",
        "spdx-tv": ".spdx",
        "cyclonedx-json": ".cdx.json",
        "cyclonedx-xml": ".cdx.xml",
    }
    return extensions.get(output_format, ".json")


def _resolve_output_path(output: Optional[Path], product: str, version: str, output_format: str) -> Optional[Path]:
    """
    Resolve the output path, inferring filename if output is a directory.

    Returns None if no output specified (stdout), or the resolved file path.
    """
    if output is None:
        return None

    # If it's an existing directory, infer filename
    if output.is_dir():
        ext = _get_format_extension(output_format)
        filename = f"{product}-{version}{ext}"
        return output / filename

    # If parent doesn't exist yet, that's fine - it will be created
    # If it's a file path, use as-is
    return output


@main.command("export")
@click.option("-p", "--product", required=True, help="Product name")
@click.option("-v", "--version", "product_version", required=True, help="Product version")
@click.option("-f", "--format", "output_format",
              type=click.Choice(["syft-json", "spdx-json", "spdx-tv", "cyclonedx-json", "cyclonedx-xml", "all"]),
              default="spdx-json", help="Output format")
@click.option("-o", "--output", type=click.Path(path_type=Path),
              help="Output file or directory (if directory, filename is inferred as product-version.ext)")
@click.pass_context
def export_cmd(ctx, product, product_version, output_format, output):
    """Export a product's SBOM to various formats."""
    # Resolve output path early, before fetching SBOM
    resolved_output = _resolve_output_path(output, product, product_version, output_format)

    if ctx.obj["local_mode"]:
        _export_local(product, product_version, output_format, resolved_output)
    else:
        _export_server(ctx, product, product_version, output_format, resolved_output)


def _export_local(product, product_version, output_format, output):
    """Export using local storage."""
    from .storage import Storage

    storage = Storage()
    sbom = storage.get_product_sbom(product, product_version)
    if not sbom:
        console.print(f"[red]No SBOM found for {product}-{product_version}[/red]")
        sys.exit(1)

    _do_export(sbom, product, product_version, output_format, output)


def _export_server(ctx, product, product_version, output_format, output):
    """Export using API server."""
    from .client import SyfterClient, APIError
    import httpx

    server_url = ctx.obj["server_url"]
    try:
        with SyfterClient(server_url) as client:
            data = client.get_sbom(product, product_version)
            sbom = json.loads(_safe_gzip_decompress(data).decode("utf-8"))
            _do_export(sbom, product, product_version, output_format, output)
    except httpx.ConnectError:
        console.print(f"[red]Error: Cannot connect to server at {server_url}[/red]")
        console.print("[dim]Is the server running? Check with: curl {}/health[/dim]".format(server_url))
        sys.exit(1)
    except APIError as e:
        console.print(f"[red]Export failed: {e}[/red]")
        sys.exit(1)


def _do_export(sbom, product, product_version, output_format, output):
    """Perform the actual export."""
    if output_format == "syft-json":
        output_str = json.dumps(sbom, indent=2)
        if output:
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_text(output_str)
            console.print(f"[green]✓ Wrote {output_format} to {output}[/green]")
        else:
            click.echo(output_str)
        return

    if output_format == "all":
        if not output:
            output = Path(".")
        output.mkdir(parents=True, exist_ok=True)
        base_name = f"{product}-{product_version}"
        results = batch_export(sbom, output, base_name)
        console.print(f"[green]✓ Exported to {len(results)} formats in {output}/[/green]")
        for fmt, path in results.items():
            console.print(f"  [dim]{path}[/dim]")
        return

    format_map = {
        "spdx-json": export_to_spdx_json,
        "spdx-tv": export_to_spdx_tv,
        "cyclonedx-json": export_to_cyclonedx_json,
        "cyclonedx-xml": export_to_cyclonedx_xml,
    }

    try:
        result = format_map[output_format](sbom, output)
        if output:
            console.print(f"[green]✓ Wrote {output_format} to {output}[/green]")
        else:
            click.echo(result)
    except ExportError as e:
        console.print(f"[red]Export failed: {e}[/red]")
        sys.exit(1)


def _format_source_type(source_type: str) -> str:
    """Format source type for display with user-friendly labels."""
    labels = {
        "container": "image",
        "directory": "RPMs",
        "archive": "zip/tar",
        "file": "file",
        "host": "system",
    }
    return labels.get(source_type, source_type or "unknown")


@main.command("products")
@click.option("--filter", "-f", "name_filter", default=None, help="Filter by product name (case-insensitive substring match)")
@click.pass_context
def list_products(ctx, name_filter):
    """List all products in the database."""
    if ctx.obj["local_mode"]:
        from .storage import Storage
        storage = Storage()
        products = storage.list_products()
    else:
        import httpx
        from .client import SyfterClient
        try:
            with SyfterClient(ctx.obj["server_url"]) as client:
                products = client.list_products()
        except httpx.ConnectError:
            console.print(f"[red]Error: Cannot connect to server at {ctx.obj['server_url']}[/red]")
            console.print("[dim]Is the server running? Check with: curl {}/health[/dim]".format(ctx.obj['server_url']))
            sys.exit(1)

    if name_filter:
        name_filter_lower = name_filter.lower()
        products = [
            p for p in products
            if name_filter_lower in (p["name"] if isinstance(p, dict) else p.name).lower()
        ]

    if not products:
        console.print("[yellow]No products found[/yellow]")
        return

    table = Table(title=f"Products ({len(products):,} total)", box=box.SIMPLE)
    table.add_column("Name", style="cyan")
    table.add_column("Version", style="green")
    table.add_column("Type", style="magenta")
    table.add_column("Scans", justify="right")
    table.add_column("Packages", justify="right")
    table.add_column("Files", justify="right")

    for p in products:
        total_files = p.get("total_files", 0) if isinstance(p, dict) else getattr(p, "total_files", 0)
        source_type = p.get("source_type") if isinstance(p, dict) else getattr(p, "source_type", None)
        table.add_row(
            p["name"] if isinstance(p, dict) else p.name,
            p["version"] if isinstance(p, dict) else p.version,
            _format_source_type(source_type),
            str(p.get("scan_count", 0) if isinstance(p, dict) else getattr(p, "scan_count", 0)),
            str(p.get("total_packages", 0) if isinstance(p, dict) else getattr(p, "total_packages", 0)),
            f"{total_files:,}" if total_files else "0",
        )
    console.print(table)


@main.command("delete")
@click.option("-p", "--product", help="Product name")
@click.option("-v", "--version", "product_version", help="Product version")
@click.option("--scan", "scan_id", type=int, help="Delete a single scan by ID")
@click.option("--yes", "-y", is_flag=True, help="Skip confirmation prompt")
@click.pass_context
def delete_product_cmd(ctx, product, product_version, scan_id, yes):
    """Delete a product (and all its scans) or a single scan.

    Examples:
        syfter delete -p myproduct -v 1.0
        syfter delete --scan 42
        syfter delete -p myproduct -v 1.0 --yes
    """
    if scan_id and product:
        console.print("[red]Use either --scan or -p/-v, not both[/red]")
        sys.exit(1)
    if not scan_id and not product:
        console.print("[red]Specify --scan ID or -p PRODUCT -v VERSION[/red]")
        sys.exit(1)
    if product and not product_version:
        console.print("[red]-v/--version is required with -p/--product[/red]")
        sys.exit(1)

    if scan_id:
        if not yes:
            confirm = click.confirm(f"Delete scan #{scan_id}?", default=False)
            if not confirm:
                console.print("[yellow]Cancelled[/yellow]")
                return

        if ctx.obj["local_mode"]:
            console.print("[red]Error: scan deletion requires server mode[/red]")
            sys.exit(1)

        import httpx
        from .client import SyfterClient, APIError
        try:
            with SyfterClient(ctx.obj["server_url"]) as client:
                client.delete_scan(scan_id)
                console.print(f"[green]Deleted scan #{scan_id}[/green]")
        except httpx.ConnectError:
            console.print(f"[red]Error: Cannot connect to server at {ctx.obj['server_url']}[/red]")
            sys.exit(1)
        except APIError as e:
            console.print(f"[red]Delete failed: {e}[/red]")
            sys.exit(1)
        return

    if not yes:
        confirm = click.confirm(
            f"Delete product '{product}-{product_version}' and all its data?",
            default=False
        )
        if not confirm:
            console.print("[yellow]Cancelled[/yellow]")
            return

    if ctx.obj["local_mode"]:
        from .storage import Storage
        storage = Storage()
        deleted = storage.delete_product(product, product_version)
        if deleted:
            console.print(f"[green]Deleted {product}-{product_version}[/green]")
        else:
            console.print(f"[red]Product {product}-{product_version} not found[/red]")
            sys.exit(1)
    else:
        import httpx
        from .client import SyfterClient, APIError
        try:
            with SyfterClient(ctx.obj["server_url"]) as client:
                client.delete_product(product, product_version)
                console.print(f"[green]Deleted {product}-{product_version}[/green]")
        except httpx.ConnectError:
            console.print(f"[red]Error: Cannot connect to server at {ctx.obj['server_url']}[/red]")
            sys.exit(1)
        except APIError as e:
            console.print(f"[red]Delete failed: {e}[/red]")
            sys.exit(1)


@main.command("rename")
@click.option("-p", "--product", required=True, help="Current product name")
@click.option("-v", "--version", "product_version", required=True, help="Current product version")
@click.option("--name", "new_name", help="New product name")
@click.option("--new-version", "new_version", help="New product version")
@click.option("--description", "new_description", help="New description")
@click.pass_context
def rename_product_cmd(ctx, product, product_version, new_name, new_version, new_description):
    """Rename or relabel a product.

    Examples:
        syfter rename -p rhel -v 10.1 --name rhel-baseos
        syfter rename -p rhel -v 10.1 --new-version 10.1-baseos
        syfter rename -p rhel -v 10.1 --description "RHEL 10.1 BaseOS x86_64"
    """
    if ctx.obj["local_mode"]:
        console.print("[red]Error: rename requires server mode[/red]")
        sys.exit(1)

    if not any([new_name, new_version, new_description]):
        console.print("[yellow]Nothing to change. Use --name, --new-version, or --description.[/yellow]")
        return

    import httpx
    from .client import SyfterClient, APIError
    try:
        with SyfterClient(ctx.obj["server_url"]) as client:
            result = client.rename_product(
                product, product_version,
                new_name=new_name,
                new_version=new_version,
                new_description=new_description,
            )
            display_name = result.get("name", new_name or product)
            display_version = result.get("version", new_version or product_version)
            console.print(f"[green]Renamed to {display_name}-{display_version}[/green]")
    except httpx.ConnectError:
        console.print(f"[red]Error: Cannot connect to server at {ctx.obj['server_url']}[/red]")
        sys.exit(1)
    except APIError as e:
        console.print(f"[red]Rename failed: {e}[/red]")
        sys.exit(1)


@main.group("tag")
@click.pass_context
def tag_group(ctx):
    """Manage tags (list, rename, delete)."""
    pass


@tag_group.command("list")
@click.option("-n", "--name", help="Filter by tag name (use %% as wildcard)")
@click.option("--limit", type=int, default=100, help="Maximum results")
@click.option("--json", "output_json", is_flag=True, help="Output as JSON")
@click.pass_context
def tag_list(ctx, name, limit, output_json):
    """List all tags with scan counts."""
    if ctx.obj["local_mode"]:
        console.print("[red]Error: tags require server mode[/red]")
        sys.exit(1)

    import httpx
    from .client import SyfterClient, APIError
    try:
        with SyfterClient(ctx.obj["server_url"]) as client:
            results = client.list_tags(name=name, limit=limit)
            if output_json:
                click.echo(json.dumps(results, indent=2))
                return
            if not results:
                console.print("[yellow]No tags found[/yellow]")
                return
            table = Table(title="Tags", box=box.SIMPLE)
            table.add_column("ID", style="dim")
            table.add_column("Name", style="cyan")
            table.add_column("Scans", justify="right", style="green")
            for t in results:
                table.add_row(str(t["id"]), t["name"], str(t.get("scan_count", 0)))
            console.print(table)
    except httpx.ConnectError:
        console.print(f"[red]Error: Cannot connect to server at {ctx.obj['server_url']}[/red]")
        sys.exit(1)
    except APIError as e:
        console.print(f"[red]Failed to list tags: {e}[/red]")
        sys.exit(1)


@tag_group.command("rename")
@click.argument("old_name")
@click.argument("new_name")
@click.pass_context
def tag_rename(ctx, old_name, new_name):
    """Rename a tag.

    Examples:
        syfter tag rename old-tag-name new-tag-name
        syfter tag rename "old tag" "new tag"
    """
    if ctx.obj["local_mode"]:
        console.print("[red]Error: tags require server mode[/red]")
        sys.exit(1)

    import httpx
    from .client import SyfterClient, APIError
    try:
        with SyfterClient(ctx.obj["server_url"]) as client:
            tags = client.list_tags(name=old_name)
            matching = [t for t in tags if t["name"] == old_name]
            if not matching:
                console.print(f"[red]Tag '{old_name}' not found[/red]")
                sys.exit(1)
            result = client.rename_tag(matching[0]["id"], new_name)
            console.print(f"[green]Renamed '{old_name}' to '{result['name']}'[/green]")
    except httpx.ConnectError:
        console.print(f"[red]Error: Cannot connect to server at {ctx.obj['server_url']}[/red]")
        sys.exit(1)
    except APIError as e:
        console.print(f"[red]Rename failed: {e}[/red]")
        sys.exit(1)


@tag_group.command("delete")
@click.argument("name")
@click.option("--yes", "-y", is_flag=True, help="Skip confirmation prompt")
@click.pass_context
def tag_delete(ctx, name, yes):
    """Delete a tag (does not delete the scans).

    Examples:
        syfter tag delete old-tag
        syfter tag delete old-tag --yes
    """
    if ctx.obj["local_mode"]:
        console.print("[red]Error: tags require server mode[/red]")
        sys.exit(1)

    if not yes:
        confirm = click.confirm(f"Delete tag '{name}'?", default=False)
        if not confirm:
            console.print("[yellow]Cancelled[/yellow]")
            return

    import httpx
    from .client import SyfterClient, APIError
    try:
        with SyfterClient(ctx.obj["server_url"]) as client:
            tags = client.list_tags(name=name)
            matching = [t for t in tags if t["name"] == name]
            if not matching:
                console.print(f"[red]Tag '{name}' not found[/red]")
                sys.exit(1)
            client.delete_tag(matching[0]["id"])
            console.print(f"[green]Deleted tag '{name}'[/green]")
    except httpx.ConnectError:
        console.print(f"[red]Error: Cannot connect to server at {ctx.obj['server_url']}[/red]")
        sys.exit(1)
    except APIError as e:
        console.print(f"[red]Delete failed: {e}[/red]")
        sys.exit(1)


@main.command("stats")
@click.pass_context
def stats(ctx):
    """Show database statistics."""
    if ctx.obj["local_mode"]:
        from .storage import Storage
        storage = Storage()
        s = storage.get_stats()
        storage_type = "local"
        db_type = "sqlite"
    else:
        import httpx
        from .client import SyfterClient
        try:
            with SyfterClient(ctx.obj["server_url"]) as client:
                s = client.get_stats()
                storage_type = s.get("storage_type", "unknown")
                db_type = s.get("database_type", "unknown")
        except httpx.ConnectError:
            console.print(f"[red]Error: Cannot connect to server at {ctx.obj['server_url']}[/red]")
            console.print("[dim]Is the server running? Check with: curl {}/health[/dim]".format(ctx.obj['server_url']))
            sys.exit(1)

    console.print(Panel(
        f"[bold]Mode:[/bold] {'Server' if not ctx.obj['local_mode'] else 'Local'}\n"
        f"[bold]Database:[/bold] {db_type}\n"
        f"[bold]Storage:[/bold] {storage_type}\n"
        f"[bold]Products:[/bold] {s.get('products', 0)}\n"
        f"[bold]Systems:[/bold] {s.get('systems', 0)}\n"
        f"[bold]Scans:[/bold] {s.get('scans', 0)}\n"
        f"[bold]Packages:[/bold] {s.get('packages', 0)}\n"
        f"[bold]Files:[/bold] {s.get('files', 0)}",
        title="Statistics",
        box=box.ROUNDED,
    ))


@main.command("check")
def check():
    """Check if syft is installed."""
    try:
        version = check_syft_installed()
        console.print(f"[green]✓ Syft is installed (version {version})[/green]")
    except SyftNotFoundError as e:
        console.print(f"[red]✗ {e}[/red]")
        sys.exit(1)



@main.command("show")
@click.option("-p", "--product", required=True, help="Product name")
@click.option("-v", "--version", "product_version", required=True, help="Product version")
@click.option("-t", "--type", "list_type",
              type=click.Choice(["files", "packages"]),
              default="files", help="What to list (files or packages)")
@click.option("--full", is_flag=True, help="Include architecture in package output (name-version.arch)")
@click.option("--layers", is_flag=True, help="Include source layer info (for container scans, packages only)")
@click.pass_context
def list_contents(ctx, product, product_version, list_type, full, layers):
    """
    List files or packages for a product version.

    Outputs a flat list to stdout, one item per line, suitable for
    piping to grep, sort, wc, etc.

    Examples:

        syfter show -p rhel -v 10.0 -t files > files.txt

        syfter show -p rhel -v 10.0 -t files | grep libssl

        syfter show -p rhel -v 10.0 -t packages | wc -l

        syfter show -p rhel -v 10.0 -t packages --full

        # List packages with source layer (format: layer::package)
        syfter show -p go-toolset -v 1.25 -t packages --layers

        # Find packages from a specific base image
        syfter show -p go-toolset -v 1.25 -t packages --layers | grep "^ubi9/ubi::"

        # Count packages per layer
        syfter show -p go-toolset -v 1.25 -t packages --layers | cut -d: -f1 | sort | uniq -c
    """
    if layers and list_type == "files":
        console.print("[yellow]Warning: --layers only applies to packages, ignoring[/yellow]")
        layers = False

    if ctx.obj["local_mode"]:
        _list_local(product, product_version, list_type, full, layers)
    else:
        _list_server(ctx, product, product_version, list_type, full, layers)


def _list_local(product, product_version, list_type, full, layers=False):
    """List using local storage."""
    from .storage import Storage

    storage = Storage()

    if list_type == "files":
        for path in storage.list_all_files(product, product_version):
            click.echo(path)
    else:
        for pkg in storage.list_all_packages(product, product_version):
            # Default: name-version, --full adds .arch
            pkg_str = pkg["name"]
            if pkg.get("version"):
                pkg_str += f"-{pkg['version']}"
            if full and pkg.get("arch"):
                pkg_str += f".{pkg['arch']}"

            # With --layers, prepend source image with :: separator
            if layers:
                source_image = pkg.get("source_image") or "(unknown)"
                out = f"{source_image}::{pkg_str}"
            else:
                out = pkg_str

            click.echo(out)


def _list_server(ctx, product, product_version, list_type, full, layers=False):
    """List using server."""
    from .client import SyfterClient, APIError
    import httpx

    server_url = ctx.obj["server_url"]
    try:
        with SyfterClient(server_url) as client:
            if list_type == "files":
                paths = client.list_all_files(product, product_version)
                for path in paths:
                    click.echo(path)
            else:
                packages = client.list_all_packages(product, product_version)
                for pkg in packages:
                    # Default: name-version, --full adds .arch
                    pkg_str = pkg["name"]
                    if pkg.get("version"):
                        pkg_str += f"-{pkg['version']}"
                    if full and pkg.get("arch"):
                        pkg_str += f".{pkg['arch']}"

                    # With --layers, prepend source image with :: separator
                    if layers:
                        source_image = pkg.get("source_image") or "(unknown)"
                        out = f"{source_image}::{pkg_str}"
                    else:
                        out = pkg_str

                    click.echo(out)
    except httpx.ConnectError:
        console.print(f"[red]Error: Cannot connect to server at {server_url}[/red]")
        sys.exit(1)
    except APIError as e:
        console.print(f"[red]List failed: {e}[/red]")
        sys.exit(1)


@main.command("trace")
@click.argument("package_name")
@click.option("--pkg-version", help="Version pattern (use %% as wildcard)")
@click.option("--json", "output_json", is_flag=True, help="Output as JSON")
@click.option("--limit", type=int, default=200, help="Maximum results per category")
@click.pass_context
def trace_cmd(ctx, package_name, pkg_version, output_json, limit):
    """Trace a package across the product stack.

    Follows a package from RHEL repos through UBI base images to layered
    containers. Shows dependency relationships (requires server mode).

    Examples:

        syfter trace systemd

        syfter trace systemd --pkg-version "252%%"

        syfter trace openssl-libs --json
    """
    if ctx.obj["local_mode"]:
        _trace_local(package_name, pkg_version, output_json, limit)
    else:
        _trace_server(ctx, package_name, pkg_version, output_json, limit)


def _trace_local(package_name, pkg_version, output_json, limit):
    """Trace using local storage (no dependency data)."""
    from .storage import Storage

    storage = Storage()
    products = storage.list_products()

    hits = []
    for p in products:
        packages = storage.list_all_packages(p["name"], p["version"])
        for pkg in packages:
            if pkg["name"] != package_name:
                continue
            if pkg_version and "%" in pkg_version:
                import fnmatch
                pattern = pkg_version.replace("%", "*")
                if not fnmatch.fnmatch(pkg.get("version", ""), pattern):
                    continue
            elif pkg_version and pkg.get("version") != pkg_version:
                continue
            hits.append({
                "product_name": p["name"],
                "product_version": p["version"],
                "package_version": pkg.get("version"),
                "arch": pkg.get("arch"),
                "source_image": pkg.get("source_image"),
            })
            if len(hits) >= limit:
                break

    result = {
        "package_name": package_name,
        "version_filter": pkg_version,
        "rhel_repos": [h for h in hits if not h.get("source_image")],
        "base_images": [],
        "layered_containers": [h for h in hits if h.get("source_image")],
        "other": [],
        "requires": [],
        "required_by": [],
    }

    if output_json:
        click.echo(json.dumps(result, indent=2))
    else:
        _display_trace(result, local_mode=True)


def _trace_server(ctx, package_name, pkg_version, output_json, limit):
    """Trace using the server API."""
    from .client import SyfterClient, APIError
    import httpx

    server_url = ctx.obj["server_url"]
    try:
        with SyfterClient(server_url) as client:
            result = client.trace_package(
                name=package_name,
                pkg_version=pkg_version,
                limit=limit,
            )

            if output_json:
                click.echo(json.dumps(result, indent=2))
            else:
                _display_trace(result, local_mode=False)
    except httpx.ConnectError:
        console.print(f"[red]Error: Cannot connect to server at {server_url}[/red]")
        sys.exit(1)
    except APIError as e:
        console.print(f"[red]Trace failed: {e}[/red]")
        sys.exit(1)


def _display_trace(result, local_mode=False):
    """Display trace results in human-readable format."""
    pkg_name = result["package_name"]
    version_filter = result.get("version_filter")
    header = f"Tracing: {pkg_name}"
    if version_filter:
        header += f"  (version: {version_filter})"
    console.print(f"\n[bold]{header}[/bold]\n")

    rhel = result.get("rhel_repos", [])
    if rhel:
        console.print("[bold cyan]RHEL Repositories[/bold cyan]")
        for h in rhel:
            line = f"  {h['product_name']:<30s} {h['product_version']:<15s} {h.get('package_version', ''):<30s} {h.get('arch', '')}"
            console.print(line)
        console.print()

    base = result.get("base_images", [])
    if base:
        console.print("[bold green]Base Images[/bold green]")
        for h in base:
            line = f"  {h['product_name']:<30s} {h['product_version']:<15s} {h.get('package_version', ''):<30s} {h.get('arch', '')}"
            console.print(line)
        console.print()

    layered = result.get("layered_containers", [])
    if layered:
        console.print("[bold magenta]Layered Containers[/bold magenta]")
        for h in layered:
            inherited = h.get("inherited_from") or h.get("source_image") or ""
            suffix = f"  (from {inherited})" if inherited else ""
            line = f"  {h['product_name']:<30s} {h['product_version']:<15s} {h.get('package_version', ''):<30s} {h.get('arch', '')}{suffix}"
            console.print(line)
        console.print()

    other = result.get("other", [])
    if other:
        console.print("[bold yellow]Other[/bold yellow]")
        for h in other:
            line = f"  {h['product_name']:<30s} {h['product_version']:<15s} {h.get('package_version', ''):<30s} {h.get('arch', '')}"
            console.print(line)
        console.print()

    if not rhel and not base and not layered and not other:
        console.print(f"[yellow]No products found containing '{pkg_name}'[/yellow]\n")
        return

    requires = result.get("requires", [])
    if requires:
        dep_names = sorted(set(r["dependency_name"] for r in requires))
        console.print("[bold]Requires[/bold]")
        console.print(f"  {', '.join(dep_names)}")
        console.print()
    elif local_mode:
        console.print("[dim]Dependency data requires server mode[/dim]\n")

    required_by = result.get("required_by", [])
    if required_by:
        pkg_names = sorted(set(r["package_name"] for r in required_by))
        console.print("[bold]Required By[/bold]")
        console.print(f"  {', '.join(pkg_names)}")
        console.print()

    total = len(rhel) + len(base) + len(layered) + len(other)
    console.print(f"[dim]Total: {total} hits across {len(set(h.get('product_name','') + '/' + h.get('product_version','') for h in rhel + base + layered + other))} products[/dim]")


@main.command("deps")
@click.argument("dependency_name", required=False)
@click.option("--package", "package_name", help="Package name (what depends on / provides)")
@click.option("--type", "dep_type", type=click.Choice(["requires", "provides"]), help="Dependency type")
@click.option("-p", "--product", "product_name", help="Filter by product name")
@click.option("-v", "--version", "product_version", help="Filter by product version")
@click.option("--limit", type=int, default=100, help="Maximum results")
@click.option("--json", "output_json", is_flag=True, help="Output as JSON")
@click.pass_context
def deps_cmd(ctx, dependency_name, package_name, dep_type, product_name, product_version, limit, output_json):
    """Query RPM dependencies (requires/provides).

    Search what packages require or provide a given dependency,
    or what dependencies a specific package has.

    Examples:

        syfter deps openssl-libs

        syfter deps --package curl --type requires

        syfter deps openssl-libs -p rhel -v 9.6

        syfter deps --json openssl-libs
    """
    if ctx.obj["local_mode"]:
        console.print("[yellow]Dependency data requires server mode.[/yellow]")
        console.print("Set SYFTER_SERVER or use --server to connect.")
        return

    from .client import SyfterClient, APIError
    import httpx

    server_url = ctx.obj["server_url"]
    try:
        with SyfterClient(server_url) as client:
            results = client.search_dependencies(
                package_name=package_name,
                dependency_name=dependency_name,
                dependency_type=dep_type,
                product_name=product_name,
                product_version=product_version,
                limit=limit,
            )

            if output_json:
                click.echo(json.dumps(results, indent=2))
                return

            if not results:
                console.print("[yellow]No dependencies found.[/yellow]")
                return

            table = Table(box=box.SIMPLE)
            table.add_column("Package", style="cyan")
            table.add_column("Version")
            table.add_column("Type", style="magenta")
            table.add_column("Dependency", style="green")
            table.add_column("Dep Version")
            table.add_column("Product")
            table.add_column("Prod Version")

            for dep in results:
                table.add_row(
                    dep.get("package_name", ""),
                    dep.get("package_version", ""),
                    dep.get("dependency_type", ""),
                    dep.get("dependency_name", ""),
                    dep.get("dependency_version", ""),
                    dep.get("product_name", ""),
                    dep.get("product_version", ""),
                )

            console.print(table)
            console.print(f"[dim]{len(results)} results[/dim]")
    except httpx.ConnectError:
        console.print(f"[red]Error: Cannot connect to server at {server_url}[/red]")
        sys.exit(1)
    except APIError as e:
        console.print(f"[red]Query failed: {e}[/red]")
        sys.exit(1)


@main.command("vulns")
@click.option("-p", "--product", required=True, help="Product name")
@click.option("-v", "--version", "product_version", required=True, help="Product version")
@click.option("--module", help="OSIDB ps_module (e.g., rhel-9). Auto-detected if omitted.")
@click.option("--env", type=click.Choice(["prod", "uat"]), default="prod", help="OSIDB environment")
@click.option("--workers", type=int, default=4, help="Parallel OSIDB query workers")
@click.option("--json", "output_json", is_flag=True, help="Output as JSON")
@click.option("-o", "--output", type=click.Path(), help="Write report to file")
@click.option("--no-cache", is_flag=True, help="Disable OSIDB affect cache")
@click.option("--cache-ttl", type=int, default=3600, help="Cache TTL in seconds")
@click.pass_context
def vulns_cmd(ctx, product, product_version, module, env, workers, output_json, output, no_cache, cache_ttl):
    """Query OSIDB for unresolved CVEs affecting a product.

    Resolves package list from syfter and correlates with OSIDB
    vulnerability data. Requires SYFTER_SERVER to be set.

    Examples:

        syfter vulns -p rhel-baseos -v 9.6

        syfter vulns -p ubi9 -v 9.7 --module rhel-9

        syfter vulns -p go-toolset -v 1.25 --json

        syfter vulns -p rhel-baseos -v 9.6 -o report.md
    """
    import concurrent.futures
    from collections import defaultdict
    from .osidb import (
        ENVS, OsidbCache, detect_module, get_affects_cached,
        get_flaws_batch, get_rh_cvss,
    )

    if ctx.obj["local_mode"]:
        console.print("[yellow]Vulnerability queries require server mode.[/yellow]")
        console.print("Set SYFTER_SERVER or use --server to connect.")
        return

    from .client import SyfterClient, APIError

    server_url = ctx.obj["server_url"]

    console.print(f"Fetching packages for {product}:{product_version}...", style="dim")
    try:
        with SyfterClient(server_url) as client:
            packages = client.list_all_packages(product, product_version)
    except Exception as e:
        console.print(f"[red]Failed to fetch packages: {e}[/red]")
        sys.exit(1)

    if not packages:
        console.print(f"[yellow]No packages found for {product}:{product_version}[/yellow]")
        return

    def _source_name(pkg):
        srpm = pkg.get("source_rpm") or ""
        if srpm:
            parts = srpm.rsplit("-", 2)
            if len(parts) >= 3:
                return parts[0]
        return pkg.get("name", "")

    components = sorted(set(_source_name(pkg) for pkg in packages))
    components = [c for c in components if c]

    if not module:
        module = detect_module(packages)
    if not module:
        console.print("[red]Could not auto-detect RHEL module. Use --module to specify.[/red]")
        sys.exit(1)

    console.print(f"  {len(packages)} packages, {len(components)} unique components", style="dim")
    console.print(f"  Module: {module}", style="dim")

    base_url = ENVS[env]
    cache = None
    if not no_cache and cache_ttl > 0:
        cache = OsidbCache(ttl=cache_ttl)

    console.print(f"Querying OSIDB ({env}) for unresolved affects...", style="dim")
    all_affects = []
    flaw_to_components = defaultdict(set)
    cache_hits = 0
    cache_misses = 0

    cached_components = set()
    if cache:
        for c in components:
            if cache.get(module, c) is not None:
                cached_components.add(c)

    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
        futures = {
            ex.submit(get_affects_cached, base_url, module, c, cache): c
            for c in components
        }
        for f in concurrent.futures.as_completed(futures):
            comp = futures[f]
            try:
                affects = f.result()
            except Exception as e:
                console.print(f"  [red]{comp}: {e}[/red]")
                continue
            was_cached = comp in cached_components
            if was_cached:
                cache_hits += 1
            else:
                cache_misses += 1
            if affects:
                console.print(f"  {comp}: {len(affects)} open affects"
                              f"{'  (cached)' if was_cached else ''}", style="dim")
            for a in affects:
                flaw_to_components[a["flaw"]].add(comp)
            all_affects.extend(affects)

    if cache:
        cache.save()

    if not all_affects:
        console.print(f"\n[green]No unresolved CVEs found for {product}:{product_version}[/green]")
        if output:
            with open(output, "w") as f:
                f.write(f"# Unresolved CVEs Report\n\n")
                f.write(f"**Product:** {product}:{product_version}\n")
                f.write(f"**Module:** {module}\n")
                f.write(f"**Components scanned:** {len(components)}\n")
                f.write(f"**Unresolved CVEs found:** 0\n")
            console.print(f"Report written to {output}")
        return

    flaw_uuids = list(flaw_to_components.keys())
    console.print(f"Fetching details for {len(flaw_uuids)} unique flaws...", style="dim")

    flaws = {}
    batch_size = 50
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
        batches = [flaw_uuids[i:i + batch_size] for i in range(0, len(flaw_uuids), batch_size)]
        futures = {ex.submit(get_flaws_batch, base_url, batch): i for i, batch in enumerate(batches)}
        for f in concurrent.futures.as_completed(futures):
            flaws.update(f.result())

    affect_details = []
    for a in all_affects:
        flaw = flaws.get(a["flaw"])
        if not flaw:
            continue
        affect_details.append({
            "cve_id": flaw.get("cve_id") or flaw["uuid"][:12],
            "impact": flaw.get("impact") or a.get("impact") or "",
            "cvss": get_rh_cvss(flaw),
            "title": flaw.get("title", ""),
            "component": a["ps_component"],
            "affectedness": a.get("affectedness", ""),
            "resolution": a.get("resolution", "") or "(none)",
            "workflow_state": flaw.get("workflow_state", ""),
        })

    seen = set()
    deduped = []
    for a in affect_details:
        key = (a["cve_id"], a["component"])
        if key not in seen:
            seen.add(key)
            deduped.append(a)

    impact_order = {"CRITICAL": 0, "IMPORTANT": 1, "MODERATE": 2, "LOW": 3, "": 4}
    deduped.sort(key=lambda a: (impact_order.get(a["impact"], 5), a["cve_id"]))

    cve_groups = defaultdict(list)
    cve_info = {}
    for a in deduped:
        cve_groups[a["cve_id"]].append(a)
        if a["cve_id"] not in cve_info:
            cve_info[a["cve_id"]] = a

    console.print(f"\n  {len(cve_groups)} unique CVEs, {len(deduped)} component-affects", style="bold")

    if output_json:
        result = {
            "product": product,
            "version": product_version,
            "module": module,
            "components_scanned": len(components),
            "cve_count": len(cve_groups),
            "affect_count": len(deduped),
            "cves": [
                {
                    "cve_id": cve_id,
                    "impact": cve_info[cve_id]["impact"],
                    "cvss": cve_info[cve_id]["cvss"],
                    "title": cve_info[cve_id]["title"],
                    "resolution": cve_info[cve_id]["resolution"],
                    "workflow_state": cve_info[cve_id]["workflow_state"],
                    "components": sorted(set(a["component"] for a in affects)),
                }
                for cve_id, affects in sorted(cve_groups.items())
            ],
        }
        if output:
            with open(output, "w") as f:
                json.dump(result, f, indent=2)
            console.print(f"JSON report written to {output}")
        else:
            click.echo(json.dumps(result, indent=2))
        return

    lines = []
    lines.append(f"# Unresolved CVEs Report\n")
    lines.append(f"**Product:** {product}:{product_version}")
    lines.append(f"**Module:** {module}")
    lines.append(f"**Components scanned:** {len(components)}")
    lines.append(f"**Unresolved CVEs found:** {len(cve_groups)}")
    lines.append(f"**Total component-affects:** {len(deduped)}")
    if cache_hits:
        lines.append(f"**Cache:** {cache_hits} hits, {cache_misses} misses")
    lines.append("")

    by_impact = defaultdict(list)
    for cve_id in cve_groups:
        info = cve_info[cve_id]
        by_impact[info["impact"]].append(cve_id)

    for imp in ["CRITICAL", "IMPORTANT", "MODERATE", "LOW", ""]:
        if imp not in by_impact:
            continue
        label = imp or "UNSET"
        cves = by_impact[imp]
        lines.append(f"## {label} ({len(cves)})\n")
        lines.append("| CVE | CVSS | Component(s) | Resolution | Status | Title |")
        lines.append("|-----|------|-------------|------------|--------|-------|")
        for cve_id in sorted(cves):
            info = cve_info[cve_id]
            comps = sorted(set(a["component"] for a in cve_groups[cve_id]))
            cvss_str = f"{info['cvss']:.1f}" if info["cvss"] is not None else "N/A"
            title = (info["title"] or "")[:80]
            lines.append(f"| {cve_id} | {cvss_str} | {', '.join(comps)} | {info['resolution']} | {info['workflow_state']} | {title} |")
        lines.append("")

    report = "\n".join(lines)
    if output:
        with open(output, "w") as f:
            f.write(report)
        console.print(f"Report written to {output}")
    else:
        click.echo(report)


@main.command("relationships")
@click.option("--limit", type=int, default=100, help="Maximum results")
@click.option("--json", "output_json", is_flag=True, help="Output as JSON")
@click.pass_context
def relationships_cmd(ctx, limit, output_json):
    """List component relationships (product-to-product mappings).

    Shows how products compose into larger products (e.g., a container
    image is a component of an operator, which is a component of a platform).

    Examples:

        syfter relationships

        syfter relationships --json

        syfter relationships --limit 50
    """
    if ctx.obj["local_mode"]:
        console.print("[yellow]Relationship data requires server mode.[/yellow]")
        console.print("Set SYFTER_SERVER or use --server to connect.")
        return

    from .client import SyfterClient, APIError
    import httpx

    server_url = ctx.obj["server_url"]
    try:
        with SyfterClient(server_url) as client:
            results = client.list_relationships(limit=limit)

            if output_json:
                click.echo(json.dumps(results, indent=2))
                return

            if not results:
                console.print("[yellow]No relationships found.[/yellow]")
                return

            table = Table(box=box.SIMPLE)
            table.add_column("ID", style="dim")
            table.add_column("Parent Product", style="cyan")
            table.add_column("Parent Version")
            table.add_column("Component Product", style="green")
            table.add_column("Component Version")
            table.add_column("Type", style="magenta")

            for rel in results:
                table.add_row(
                    str(rel.get("id", "")),
                    rel.get("parent_product_name", ""),
                    rel.get("parent_product_version", ""),
                    rel.get("component_product_name", ""),
                    rel.get("component_product_version", ""),
                    rel.get("relationship_type", ""),
                )

            console.print(table)
            console.print(f"[dim]{len(results)} relationships[/dim]")
    except httpx.ConnectError:
        console.print(f"[red]Error: Cannot connect to server at {server_url}[/red]")
        sys.exit(1)
    except APIError as e:
        console.print(f"[red]Query failed: {e}[/red]")
        sys.exit(1)


@main.command("layers", hidden=True)
@click.option("-p", "--product", required=True, help="Product name")
@click.option("-v", "--version", "product_version", required=True, help="Product version")
@click.option("--json", "output_json", is_flag=True, help="Output as JSON")
@click.pass_context
def show_layers(ctx, product, product_version, output_json):
    """
    Show container layers for a product.

    Displays the layer chain for a container image, showing which source
    image contributed each layer. Only available for container scans.

    Examples:

        syfter layers -p go-toolset -v 1.25  (deprecated, use 'show')

        syfter layers -p go-toolset -v 1.25 --json
    """
    if ctx.obj["local_mode"]:
        _layers_local(product, product_version, output_json)
    else:
        _layers_server(ctx, product, product_version, output_json)


def _layers_local(product, product_version, output_json):
    """Show layers using local storage."""
    from .storage import Storage

    storage = Storage()
    result = storage.get_product_layers(product, product_version)

    if not result:
        console.print(f"[yellow]No layer information found for {product}-{product_version}[/yellow]")
        console.print("[dim]Layer info is only available for container scans.[/dim]")
        return

    _display_layers(result, output_json)


def _layers_server(ctx, product, product_version, output_json):
    """Show layers using server."""
    from .client import SyfterClient, APIError
    import httpx

    server_url = ctx.obj["server_url"]
    try:
        with SyfterClient(server_url) as client:
            result = client.get_product_layers(product, product_version)

            if not result:
                console.print(f"[yellow]No layer information found for {product}-{product_version}[/yellow]")
                console.print("[dim]Layer info is only available for container scans.[/dim]")
                return

            _display_layers(result, output_json)
    except httpx.ConnectError:
        console.print(f"[red]Error: Cannot connect to server at {server_url}[/red]")
        sys.exit(1)
    except APIError as e:
        if "404" in str(e):
            console.print(f"[yellow]No layer information found for {product}-{product_version}[/yellow]")
            console.print("[dim]Layer info is only available for container scans.[/dim]")
        else:
            console.print(f"[red]Failed to get layers: {e}[/red]")
        sys.exit(1)


def _display_layers(result, output_json):
    """Display layer information."""
    if output_json:
        click.echo(json.dumps(result, indent=2))
        return

    layers = result.get("layers", [])
    source_path = result.get("source_path", "unknown")

    console.print(Panel(
        f"[bold]Container:[/bold] {source_path}\n"
        f"[bold]Layers:[/bold] {len(layers)}",
        title="Container Layer Chain",
        box=box.ROUNDED,
    ))

    table = Table(box=box.SIMPLE)
    table.add_column("#", style="dim", width=3)
    table.add_column("Layer ID", style="cyan", width=15)
    table.add_column("Source Image", style="green")
    table.add_column("Version", style="yellow")
    table.add_column("Image Reference (copy/paste)", style="magenta")

    for layer in layers:
        idx = layer.get("layer_index", 0)
        layer_id = layer.get("layer_id", "")
        source_image = layer.get("source_image") or "(unknown)"
        source_version = layer.get("source_version") or ""
        image_ref = layer.get("image_reference") or ""

        table.add_row(
            str(idx),
            layer_id,
            source_image,
            source_version,
            image_ref,
        )

    console.print(table)

    # Print summary
    unique_images = set(l.get("source_image") for l in layers if l.get("source_image"))
    console.print()
    console.print(f"[dim]Unique source images: {len(unique_images)}[/dim]")
    for img in sorted(unique_images):
        # Find the reference for this image
        ref = next((l.get("image_reference") for l in layers if l.get("source_image") == img), None)
        if ref:
            console.print(f"[dim]  • {img} -> [cyan]{ref}[/cyan][/dim]")
        else:
            console.print(f"[dim]  • {img}[/dim]")



# ============================================================================
# System commands (infrastructure mode)
# ============================================================================

@main.command("systems", hidden=True)
@click.option("--tag", help="Filter by system tag")
@click.pass_context
def list_systems(ctx, tag):
    """List all systems in the database (infrastructure mode)."""
    if ctx.obj["local_mode"]:
        console.print("[yellow]Systems are only available in server mode[/yellow]")
        return

    import httpx
    from .client import SyfterClient
    try:
        with SyfterClient(ctx.obj["server_url"]) as client:
            systems = client.list_systems(tag=tag)
    except httpx.ConnectError:
        console.print(f"[red]Error: Cannot connect to server at {ctx.obj['server_url']}[/red]")
        sys.exit(1)

    if not systems:
        console.print("[yellow]No systems found[/yellow]")
        return

    table = Table(title="Systems", box=box.SIMPLE)
    table.add_column("Hostname", style="cyan")
    table.add_column("IP", style="dim")
    table.add_column("Tag", style="magenta")
    table.add_column("OS", style="green")
    table.add_column("Packages", justify="right")
    table.add_column("Files", justify="right")
    table.add_column("Last Scan", style="dim")

    for s in systems:
        os_info = ""
        if s.get("os_name"):
            os_info = s["os_name"]
            if s.get("os_version"):
                os_info += f" {s['os_version']}"

        last_scan = ""
        if s.get("last_scan_at"):
            last_scan = s["last_scan_at"][:10]

        table.add_row(
            s["hostname"],
            s.get("ip_address") or "",
            s.get("tag") or "",
            os_info,
            str(s.get("total_packages", 0)),
            f"{s.get('total_files', 0):,}" if s.get('total_files') else "0",
            last_scan,
        )
    console.print(table)


@main.command("system-query", hidden=True)
@click.option("-n", "--name", help="Package name pattern (use %% as wildcard)")
@click.option("-f", "--file", "file_path", help="File path pattern")
@click.option("-d", "--digest", help="File digest (exact match)")
@click.option("-H", "--hostname", help="Filter by hostname")
@click.option("-t", "--tag", help="Filter by system tag")
@click.option("--limit", type=int, default=50, help="Maximum results")
@click.option("--json", "output_json", is_flag=True, help="Output as JSON")
@click.pass_context
def system_query(ctx, name, file_path, digest, hostname, tag, limit, output_json):
    """Query packages and files across systems (infrastructure mode)."""
    if ctx.obj["local_mode"]:
        console.print("[yellow]System queries are only available in server mode[/yellow]")
        return

    from .client import SyfterClient, APIError
    import httpx

    server_url = ctx.obj["server_url"]
    try:
        with SyfterClient(server_url) as client:
            if file_path or digest:
                results = client.search_system_files(
                    path=file_path, digest=digest,
                    hostname=hostname, tag=tag, limit=limit
                )
                if output_json:
                    click.echo(json.dumps(results, indent=2))
                    return
                if not results:
                    console.print("[yellow]No files found[/yellow]")
                    return
                table = Table(title="System File Search Results", box=box.SIMPLE)
                table.add_column("Path", style="cyan")
                table.add_column("Package", style="green")
                table.add_column("System", style="magenta")
                table.add_column("Tag", style="dim")
                for row in results:
                    pkg_info = row['package_name']
                    if row.get('package_version'):
                        pkg_info += f"-{row['package_version']}"
                    table.add_row(
                        row["path"],
                        pkg_info,
                        row["system_hostname"],
                        row.get("system_tag") or "",
                    )
                console.print(table)

            elif name:
                results = client.search_system_packages(
                    name=name, hostname=hostname, tag=tag, limit=limit
                )
                if output_json:
                    click.echo(json.dumps(results, indent=2))
                    return
                if not results:
                    console.print("[yellow]No packages found[/yellow]")
                    return
                table = Table(title="System Package Search Results", box=box.SIMPLE)
                table.add_column("Name", style="cyan")
                table.add_column("Version", style="green")
                table.add_column("System", style="magenta")
                table.add_column("Tag", style="dim")
                for row in results:
                    table.add_row(
                        row["name"],
                        row["version"] or "",
                        row["system_hostname"],
                        row.get("system_tag") or "",
                    )
                console.print(table)
            else:
                console.print("[yellow]Please specify --name, --file, or --digest[/yellow]")
    except httpx.ConnectError:
        console.print(f"[red]Error: Cannot connect to server at {server_url}[/red]")
        sys.exit(1)
    except APIError as e:
        console.print(f"[red]Query failed: {e}[/red]")
        sys.exit(1)


@main.command("system-list", hidden=True)
@click.option("-H", "--hostname", required=True, help="System hostname")
@click.option("-t", "--type", "list_type",
              type=click.Choice(["files", "packages"]),
              default="files", help="What to list (files or packages)")
@click.option("--full", is_flag=True, help="Include architecture in package output")
@click.pass_context
def system_list_contents(ctx, hostname, list_type, full):
    """
    List files or packages for a system (infrastructure mode).

    Outputs a flat list to stdout, one item per line, suitable for
    piping to grep, sort, wc, etc.
    """
    if ctx.obj["local_mode"]:
        console.print("[yellow]System list is only available in server mode[/yellow]")
        return

    from .client import SyfterClient, APIError
    import httpx

    server_url = ctx.obj["server_url"]
    try:
        with SyfterClient(server_url) as client:
            if list_type == "files":
                paths = client.list_system_files(hostname)
                for path in paths:
                    click.echo(path)
            else:
                packages = client.list_system_packages(hostname)
                for pkg in packages:
                    # Default: name-version, --full adds .arch
                    out = pkg["name"]
                    if pkg.get("version"):
                        out += f"-{pkg['version']}"
                    if full and pkg.get("arch"):
                        out += f".{pkg['arch']}"
                    click.echo(out)
    except httpx.ConnectError:
        console.print(f"[red]Error: Cannot connect to server at {server_url}[/red]")
        sys.exit(1)
    except APIError as e:
        console.print(f"[red]List failed: {e}[/red]")
        sys.exit(1)


@main.command("system-scan", hidden=True)
@click.argument("target", default="localhost")
@click.option("-t", "--tag", help="System tag for grouping/filtering (e.g., 'production', 'web-servers')")
@click.option("-u", "--user", help="SSH user for remote hosts")
@click.option("-p", "--port", type=int, default=22, help="SSH port for remote hosts")
@click.option("-i", "--identity", type=click.Path(exists=True), help="SSH identity file")
@click.option("-o", "--output", type=click.Path(path_type=Path), help="Write SBOM to file")
@click.option("--no-store", is_flag=True, help="Don't store (just output)")
@click.option("-q", "--quiet", is_flag=True, help="Suppress progress output")
@click.option("--skip-files", is_flag=True, help="Skip file indexing (faster, uses less memory)")
@click.option("--include-debug", is_flag=True, help="Include debuginfo/debugsource packages")
@click.pass_context
def system_scan(
    ctx,
    target: str,
    tag: Optional[str],
    user: Optional[str],
    port: int,
    identity: Optional[str],
    output: Optional[Path],
    no_store: bool,
    quiet: bool,
    skip_files: bool,
    include_debug: bool,
):
    """
    Scan a system and store the SBOM for infrastructure tracking.

    TARGET can be 'localhost' (default) or a remote hostname/IP for SSH scanning.

    Examples:

        # Scan the local system
        syfter system-scan

        # Scan with a tag for grouping
        syfter system-scan --tag production

        # Scan a remote host via SSH
        syfter system-scan webserver01.example.com

        # Scan remote host with specific SSH options
        syfter system-scan 192.168.1.100 -u admin -i ~/.ssh/server_key
    """
    if ctx.obj["local_mode"]:
        console.print("[yellow]System scanning requires server mode. Set SYFTER_SERVER environment variable.[/yellow]")
        sys.exit(1)

    try:
        check_syft_installed()
    except SyftNotFoundError as e:
        console.print(f"[red]Error: {e}[/red]")
        sys.exit(1)

    # Determine if scanning localhost or remote
    is_localhost = target.lower() in ("localhost", "127.0.0.1", "::1")

    # Get host info
    if is_localhost:
        host_info = get_host_info()
    else:
        console.print(f"[dim]Getting info from remote host {target}...[/dim]")
        try:
            host_info = get_remote_host_info(target, user=user, port=port, identity_file=identity)
        except Exception as e:
            console.print(f"[red]Failed to connect to {target}: {e}[/red]")
            sys.exit(1)

    if tag:
        host_info["tag"] = tag

    console.print(Panel(
        f"[bold]Scanning:[/bold] {target}\n"
        f"[bold]Hostname:[/bold] {host_info['hostname']}\n"
        f"[bold]IP:[/bold] {host_info.get('ip_address', 'unknown')}\n"
        f"[bold]OS:[/bold] {host_info.get('os_name', '')} {host_info.get('os_version', '')}\n"
        f"[bold]Tag:[/bold] {tag or '(none)'}",
        title="Syfter System Scan",
        box=box.ROUNDED,
    ))

    try:
        exclude_debug = not include_debug
        if is_localhost:
            original_sbom, syft_version = scan_localhost(
                show_progress=not quiet,
                exclude_debug=exclude_debug,
            )
        else:
            original_sbom, syft_version = scan_remote_host(
                host=target,
                user=user,
                port=port,
                identity_file=identity,
                show_progress=not quiet,
                exclude_debug=exclude_debug,
            )
    except ScanError as e:
        console.print(f"[red]Scan failed: {e}[/red]")
        sys.exit(1)

    # Create a pseudo-product for modification (reuse existing infrastructure)
    from .models import Product
    pseudo_product = Product(
        name=host_info["hostname"],
        version=host_info.get("os_version", "unknown"),
        vendor="",
        cpe_vendor="",
        purl_namespace="",
        description=f"System scan of {host_info['hostname']}",
    )

    modified_sbom = modify_sbom(original_sbom, pseudo_product, exclude_debug=not include_debug)
    packages = extract_packages(modified_sbom, skip_files=skip_files)

    if skip_files:
        console.print("[yellow]Note: File indexing skipped (--skip-files). File search won't work for this scan.[/yellow]")

    if output:
        output.write_text(json.dumps(modified_sbom, indent=2))
        console.print(f"[green]Wrote SBOM to {output}[/green]")

    if no_store:
        console.print("[yellow]Skipped storage (--no-store)[/yellow]")
        return

    # Store to server
    _store_system_server(ctx, host_info, syft_version, original_sbom, modified_sbom, packages)


def _store_system_server(ctx, host_info, syft_version, original_sbom, modified_sbom, packages):
    """Store system scan using API server with async job-based flow."""
    from .client import SyfterClient, APIError
    import httpx

    server_url = ctx.obj["server_url"]
    try:
        with SyfterClient(server_url) as client:
            # Use async job-based upload for memory efficiency
            result = client.upload_system_scan_async(
                hostname=host_info["hostname"],
                ip_address=host_info.get("ip_address"),
                os_name=host_info.get("os_name"),
                os_version=host_info.get("os_version"),
                architecture=host_info.get("architecture"),
                tag=host_info.get("tag"),
                syft_version=syft_version,
                original_sbom=original_sbom,
                modified_sbom=modified_sbom,
                packages=packages,
            )
            scan_id = result.get("scan_id", "unknown")
            console.print(f"[green]✓ System scan #{scan_id} uploaded to server (job: {result['id']})[/green]")
    except httpx.ConnectError:
        console.print(f"[red]Error: Cannot connect to server at {server_url}[/red]")
        console.print("[dim]Is the server running? Check with: curl {}/health[/dim]".format(server_url))
        sys.exit(1)
    except APIError as e:
        console.print(f"[red]Upload failed: {e}[/red]")
        sys.exit(1)


if __name__ == "__main__":
    main()
