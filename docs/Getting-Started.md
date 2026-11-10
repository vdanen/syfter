# Syfter Getting Started Guide

Syfter collects and catalogs SBOM data from RPM repositories, container images, and other sources. Its API server, web dashboard, and CLI support SBOM and package-list imports, package and dependency queries, scan tagging, and SBOM export.

## Prerequisites

- Python 3.11+ installed
- [uv](https://docs.astral.sh/uv/) package manager (recommended) or pip
- An API key (provided by your team lead)
- VPN access to the Red Hat network (for browser access)

## 1. Install the CLI

Install the CLI from the [syfter](https://github.com/vdanen/syfter) repository. This includes built-in API key authentication support.

### macOS

```bash
uv tool install git+https://github.com/vdanen/syfter
```

Or with pip:

```bash
pip install git+https://github.com/vdanen/syfter
```

### Linux

```bash
pip install git+https://github.com/vdanen/syfter
```

If you hit PEP 668 restrictions on your distro, use `pipx` or a virtual environment:

```bash
pipx install git+https://github.com/vdanen/syfter
```

### Verify

```bash
syfter --version
```

> **Note:** Use Syfter 0.9.2.0 or newer for API key authentication. Check the installed version with `syfter --version`.

## 2. Configure Environment Variables

You need two environment variables:

| Variable | Description |
|----------|-------------|
| `SYFTER_SERVER` | The API server URL |
| `SYFTER_API_KEY` | Your personal API key |

### macOS (zsh)

Add to `~/.zshrc`:

```bash
echo 'export SYFTER_SERVER=https://syfter-cli-syfter.__CLUSTER_DOMAIN__' >> ~/.zshrc
echo 'export SYFTER_API_KEY=<your-api-key>' >> ~/.zshrc
```

Reload your shell:

```bash
source ~/.zshrc
```

### Linux (bash)

Add to `~/.bashrc`:

```bash
echo 'export SYFTER_SERVER=https://syfter-cli-syfter.__CLUSTER_DOMAIN__' >> ~/.bashrc
echo 'export SYFTER_API_KEY=<your-api-key>' >> ~/.bashrc
```

Reload your shell:

```bash
source ~/.bashrc
```

> **Note:** If your Linux distribution uses a different default shell (e.g., fish, zsh), add the exports to the appropriate config file for that shell.

### Verify Configuration

```bash
syfter stats
```

You should see output like:

```
Products: 3,220
Scans:    3,216
Packages: 11,265,041
Storage:  s3
Database: postgresql
```

## 3. Browser Access

The web interface is available at:

```
https://syfter-api-syfter.__CLUSTER_DOMAIN__/dashboard/
```

Log in with the Keycloak credentials provided to you (your `@redhat.com` email and password).

> **Note:** The cluster operates on a schedule (8 AM - 8 PM ET, Monday - Friday). The service is unavailable outside these hours and on weekends.

## 4. Common Commands

### View Statistics

```bash
syfter stats
```

### List All Products

```bash
syfter products
```

### Search for Packages

Use `%` as a wildcard character:

```bash
# Search for packages starting with "openssl"
syfter query -n "openssl%"

# Search for an exact package name
syfter query -n "bash"

# Search within a specific product
syfter query -n "openssl%" -p rhel -v 10.0

# Output results as JSON
syfter query -n "curl%" --json

# Limit results
syfter query -n "lib%" --limit 10
```

### List Packages in a Product

```bash
# List all packages in a product version
syfter list -p rhel -v 10.0 -t packages

# Include architecture details
syfter list -p rhel -v 10.0 -t packages --full

# Pipe to standard tools
syfter list -p rhel -v 10.0 -t packages | wc -l
syfter list -p rhel -v 10.0 -t packages | grep ssl
```

### Export SBOMs

Export in various standard formats:

```bash
# Export as SPDX JSON
syfter export -p rhel -v 10.0 -f spdx-json -o rhel-10.0.spdx.json

# Export as CycloneDX JSON
syfter export -p rhel -v 10.0 -f cyclonedx-json -o rhel-10.0.cdx.json

# Export in syft's native JSON format
syfter export -p rhel -v 10.0 -f syft-json -o rhel-10.0.syft.json

# Export all formats at once to a directory
syfter export -p rhel -v 10.0 -f all -o ./exports/
```

### Scan a Target

Scan an RPM directory or container image and upload the SBOM:

```bash
# Scan a local RPM directory
syfter scan /path/to/Packages -p rhel -v 10.1 --description "RHEL 10.1 BaseOS x86_64"

# Scan a container image
syfter scan registry.redhat.io/ubi9/ubi:latest -p ubi9 -v latest

# Scan without uploading (local only)
syfter scan /path/to/Packages -p rhel -v 10.1 --no-store -o output.json
```

### Delete a Product

```bash
syfter delete -p myproduct -v 1.0
```

## 5. Troubleshooting

### `API error 401: Missing or invalid API key`

Two possible causes:

1. **API key not set.** Verify it is exported:
   ```bash
   echo $SYFTER_API_KEY
   ```
   If empty, re-run the export commands from step 2 and reload your shell.

2. **Wrong syfter version installed.** Install from [github.com/vdanen/syfter](https://github.com/vdanen/syfter) as described in step 1 to get API key support. Check which version you have:
   ```bash
   which syfter
   syfter --version
   ```
   If the version is older than `0.9.1.0`, uninstall and reinstall from step 1.

### Connection refused / host unreachable

The cluster is only available Monday - Friday, 8 AM - 8 PM ET. Check the current time and try again during business hours.

### Command not found: syfter

The CLI is not installed or not on your PATH. Reinstall with `uv tool install` and ensure `~/.local/bin` is in your PATH:

```bash
# macOS
echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.zshrc && source ~/.zshrc

# Linux
echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.bashrc && source ~/.bashrc
```

### Stats shows 0 packages / empty results

The stats endpoint caches results for 5 minutes. If the server was just restarted, the first call may take ~15 seconds while the cache warms up. Subsequent calls return instantly.

## 6. Rate Limits

The API enforces per-key rate limits to ensure fair usage:

| Operation | Limit | Burst |
|-----------|-------|-------|
| Queries (`GET`) | 60/min | 20 |
| Uploads (`POST`) | 10/min | 5 |

If you hit a rate limit, the response will include a `Retry-After` header indicating when to retry. Normal interactive usage will not hit these limits.

## 7. Getting Help

```bash
# General help
syfter --help

# Help for a specific command
syfter query --help
syfter scan --help
```

For issues with the service, contact the Product Security team.
