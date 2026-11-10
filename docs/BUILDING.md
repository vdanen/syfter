# Building and Distributing Syfter

This guide covers building syfter for distribution to client environments.

## Version

Current version: **0.9.2.0**

Version is defined in:
- `pyproject.toml` - Package metadata
- `syfter/__init__.py` - CLI version (`syfter --version`)
- `server/main.py` - API version

## Build Options

Syfter can be distributed in several ways:

| Method | Best For | Includes Server |
|--------|----------|-----------------|
| PyPI package | Standard Python environments | Optional |
| Wheel file | Offline/air-gapped systems | Optional |
| Container image | Server deployment | Yes |
| RPM package | RHEL/Fedora systems | Optional |

---

## 1. Python Package (PyPI / wheel)

### Prerequisites

```bash
# Option A: Using uv (recommended)
# Install uv if not already installed
curl -LsSf https://astral.sh/uv/install.sh | sh

# Option B: Using traditional tools
pip install build twine
```

### Build the Package

```bash
cd /path/to/syfter

# Using uv (recommended)
uv build

# Or using traditional tools
python -m build

# Output will be in dist/
ls dist/
# syfter-0.9.0.tar.gz
# syfter-0.9.0-py3-none-any.whl
```

### Install as a CLI Tool (uv)

The recommended way to install syfter as a standalone CLI tool:

```bash
# Install from PyPI (after publishing)
uv tool install syfter

# Install with server components
uv tool install "syfter[server]"

# Install from local directory (for testing)
uv tool install .

# Install from local wheel
uv tool install dist/syfter-0.9.0-py3-none-any.whl

# Install from GitHub
uv tool install git+https://github.com/vdanen/syfter

# Upgrade to latest version
uv tool upgrade syfter

# Uninstall
uv tool uninstall syfter
```

### Install with pip

```bash
# Client-only installation (CLI + local SQLite)
pip install syfter-0.9.0-py3-none-any.whl

# Full installation with server components
pip install "syfter-0.9.0-py3-none-any.whl[server]"

# Development installation
pip install "syfter-0.9.0-py3-none-any.whl[all]"
```

### Publish to PyPI

```bash
# Using uv (recommended)
uv publish

# Or using twine
twine upload dist/*

# Upload to internal PyPI server
twine upload --repository-url https://pypi.internal.example.com/simple/ dist/*
```

> **Note:** Publishing requires a PyPI account. Create one at https://pypi.org/account/register/
> and generate an API token at https://pypi.org/manage/account/token/

---

## 2. Container Images

### Build Client Image

For lightweight client-only deployments:

```dockerfile
# Containerfile.client
FROM registry.access.redhat.com/ubi9/python-311:latest

WORKDIR /app

# Install syft
RUN curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin

# Copy and install syfter
COPY dist/syfter-*.whl /tmp/
RUN pip install /tmp/syfter-*.whl

# Set default server (override at runtime)
ENV SYFTER_SERVER=""

ENTRYPOINT ["syfter"]
```

Build:
```bash
# Build wheel first
python -m build

# Build container
podman build -f Containerfile.client -t syfter-client:0.9.0 .
```

Usage:
```bash
# Run scan against external server
podman run --rm \
  -e SYFTER_SERVER=http://syfter.example.com:8000 \
  -v /path/to/rpms:/scan:ro \
  syfter-client:0.9.0 scan /scan -p myproduct -v 1.0
```

### Build Server Image

The server image is built via the existing `podman/Containerfile`:

```bash
cd podman
podman build -f Containerfile -t syfter-server:0.9.0 ..
```

### Multi-Architecture Builds

For both AMD64 and ARM64:

```bash
# Create builder (one time)
podman manifest create syfter-server:0.9.0

# Build for each architecture
podman build --platform linux/amd64 -t syfter-server:0.9.0-amd64 .
podman build --platform linux/arm64 -t syfter-server:0.9.0-arm64 .

# Add to manifest
podman manifest add syfter-server:0.9.0 syfter-server:0.9.0-amd64
podman manifest add syfter-server:0.9.0 syfter-server:0.9.0-arm64

# Push manifest
podman manifest push syfter-server:0.9.0 registry.example.com/syfter-server:0.9.0
```

---

## 3. RPM Package

### Create RPM Spec

```bash
mkdir -p ~/rpmbuild/{SPECS,SOURCES}
```

Create `~/rpmbuild/SPECS/syfter.spec`:

```spec
Name:           syfter
Version:        0.9.0
Release:        1%{?dist}
Summary:        SBOM generation and management tool using Syft

License:        Apache-2.0
URL:            https://github.com/vdanen/syfter
Source0:        %{name}-%{version}.tar.gz

BuildArch:      noarch
BuildRequires:  python3-devel
BuildRequires:  python3-pip
BuildRequires:  python3-setuptools
BuildRequires:  python3-wheel

Requires:       python3 >= 3.11
Requires:       python3-click >= 8.0
Requires:       python3-pyyaml >= 6.0
Requires:       python3-rich >= 13.0
Requires:       python3-httpx >= 0.25
Requires:       syft >= 1.0

%description
Syfter is an SBOM (Software Bill of Materials) generation and management 
tool built on top of Syft. It provides product-specific metadata injection,
local SQLite storage for querying, and export to SPDX/CycloneDX formats.

%package server
Summary:        Syfter API server components
Requires:       %{name} = %{version}-%{release}
Requires:       python3-fastapi >= 0.109
Requires:       python3-uvicorn >= 0.27
Requires:       python3-sqlalchemy >= 2.0
Requires:       python3-psycopg2 >= 2.9
Requires:       python3-boto3 >= 1.34

%description server
Server components for distributed Syfter deployments with PostgreSQL
and S3/MinIO storage.

%prep
%autosetup -n %{name}-%{version}

%build
%py3_build

%install
%py3_install

# Install systemd service files
install -D -m 644 contrib/syfter-server.service %{buildroot}%{_unitdir}/syfter-server.service

%files
%license LICENSE
%doc README.md docs/
%{python3_sitelib}/syfter/
%{python3_sitelib}/syfter-%{version}*
%{_bindir}/syfter

%files server
%{python3_sitelib}/server/
%{_bindir}/syfter-server
%{_unitdir}/syfter-server.service

%changelog
* Tue Jan 14 2026 Red Hat <sbom@redhat.com> - 0.9.0-1
- Initial release
- Renamed from rh-syfter to syfter
- Added container layer tracking
- Added system mode for host scanning
- Security hardening
```

### Build RPM

```bash
# Create source tarball
git archive --prefix=syfter-0.9.0/ -o ~/rpmbuild/SOURCES/syfter-0.9.0.tar.gz HEAD

# Build RPM
rpmbuild -ba ~/rpmbuild/SPECS/syfter.spec
```

---

## 4. Offline/Air-Gapped Installation

For environments without internet access:

### Create Offline Bundle

```bash
# Create directory for offline bundle
mkdir -p syfter-offline-0.9.0

# Download syfter wheel
pip download -d syfter-offline-0.9.0/ syfter==0.9.0

# Or build from source
python -m build
cp dist/syfter-0.9.0-py3-none-any.whl syfter-offline-0.9.0/

# Download all dependencies
pip download -d syfter-offline-0.9.0/ \
  click>=8.0 \
  pyyaml>=6.0 \
  rich>=13.0 \
  packageurl-python>=0.11 \
  httpx>=0.25

# For server installations, also download:
pip download -d syfter-offline-0.9.0/ \
  fastapi>=0.109 \
  uvicorn[standard]>=0.27 \
  sqlalchemy>=2.0 \
  psycopg2-binary>=2.9 \
  boto3>=1.34 \
  python-multipart>=0.0.6

# Download syft binary
curl -Lo syfter-offline-0.9.0/syft-linux-amd64 \
  https://github.com/anchore/syft/releases/download/v1.18.1/syft_1.18.1_linux_amd64

# Create tarball
tar czvf syfter-offline-0.9.0.tar.gz syfter-offline-0.9.0/
```

### Install from Offline Bundle

```bash
# Extract bundle
tar xzf syfter-offline-0.9.0.tar.gz
cd syfter-offline-0.9.0

# Install syfter and dependencies
pip install --no-index --find-links . syfter-0.9.0-py3-none-any.whl

# For server installation
pip install --no-index --find-links . "syfter-0.9.0-py3-none-any.whl[server]"

# Install syft binary
chmod +x syft-linux-amd64
sudo mv syft-linux-amd64 /usr/local/bin/syft
```

---

## 5. Development Installation

For contributors and testing:

### Using uv (recommended)

```bash
# Clone repository
git clone https://github.com/vdanen/syfter.git
cd syfter

# Create virtual environment and install dependencies
uv venv
source .venv/bin/activate
uv pip install -e ".[all]"

# Or use uv sync if you have a uv.lock file
uv sync --all-extras

# Verify installation
syfter --version
# syfter version 0.9.0

# Run tests
./scripts/run-tests.sh local
./scripts/run-tests.sh coverage
```

The test runner installs the editable project with the `[all]` extra before
running tests. This includes both the test tools and server dependencies, which
the test modules import during collection.

### Using pip

```bash
# Clone repository
git clone https://github.com/vdanen/syfter.git
cd syfter

# Create virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install in development mode with all dependencies
pip install -e ".[all]"

# Verify installation
syfter --version
# syfter version 0.9.0

# Run tests
./scripts/run-tests.sh local
./scripts/run-tests.sh coverage
```

---

## Release Checklist

When preparing a new release:

1. **Update version numbers:**
   ```bash
   # Files to update:
   # - pyproject.toml (version = "X.Y.Z")
   # - syfter/__init__.py (__version__ = "X.Y.Z")
   # - server/main.py (__version__ = "X.Y.Z")
   ```

2. **Update changelog:**
   - Add entry to CHANGELOG.md (if exists)
   - Update RPM spec changelog

3. **Run tests:**
   ```bash
   ./scripts/run-tests.sh all
   ```

4. **Build artifacts:**
   ```bash
   python -m build
   ```

5. **Test installation:**
   ```bash
   # Fresh venv
   python -m venv /tmp/test-venv
   source /tmp/test-venv/bin/activate
   pip install dist/syfter-*.whl
   syfter --version
   syfter check
   ```

6. **Tag release:**
   ```bash
   git tag -a v0.9.0 -m "Release 0.9.0"
   git push origin v0.9.0
   ```

7. **Publish:**
   ```bash
   twine upload dist/*
   ```

---

## Client Requirements

### Minimum Requirements

- Python 3.11+
- 100MB disk space
- Network access to Syfter server (for server mode)

### Optional Requirements

- **syft** (for scanning) - https://github.com/anchore/syft
- **skopeo** (for container layer analysis) - https://github.com/containers/skopeo

### Installing Prerequisites

**RHEL/Fedora:**
```bash
sudo dnf install python3 python3-pip skopeo

# Install syft
curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sudo sh -s -- -b /usr/local/bin
```

**Ubuntu/Debian:**
```bash
sudo apt install python3 python3-pip skopeo

# Install syft
curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sudo sh -s -- -b /usr/local/bin
```

**macOS:**
```bash
brew install python@3.11 syft skopeo
```

---

## Verification

After installation, verify syfter is working:

```bash
# Check version
syfter --version

# Check dependencies
syfter check

# Test local mode (creates ~/.syfter/syfter.db)
syfter stats

# Test server mode
export SYFTER_SERVER=http://your-server:8000
syfter stats
```

## Quick Start for End Users

Once published to PyPI, end users can install and use syfter with:

```bash
# Install using uv (recommended - isolated tool installation)
uv tool install syfter

# Or install using pipx (alternative isolated installation)
pipx install syfter

# Or install using pip (into current environment)
pip install syfter

# Verify it works
syfter --version
syfter check
```
