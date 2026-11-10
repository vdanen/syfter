# Syfter Deployment Guide

This guide covers deploying the Syfter server and clients for production use.

For the complete environment-variable list, see [Server Configuration](SERVER-CONFIGURATION.md). For route details, see the [API Reference](API-REFERENCE.md).

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                      Syfter Clients                             │
│  (scan targets, upload SBOMs, query packages, export SBOMs)     │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                      Syfter API Server                          │
│                    (FastAPI, 20-30 clients)                     │
└─────────────────────────────────────────────────────────────────┘
           │                                    │
           ▼                                    ▼
┌─────────────────────┐              ┌─────────────────────┐
│     PostgreSQL      │              │   MinIO / S3        │
│   (indexed data)    │              │  (SBOM storage)     │
│   ~50GB for 1000    │              │  ~500GB for 1000    │
│     scans           │              │     scans           │
└─────────────────────┘              └─────────────────────┘
```

## Quick Start with Podman Compose

The easiest way to deploy is using Podman Compose:

```bash
cd podman

# Create .env file with secrets
cat > .env << EOF
POSTGRES_PASSWORD=your_secure_password
MINIO_ROOT_USER=minio_admin
MINIO_ROOT_PASSWORD=your_minio_password
EOF

# Start all services
podman-compose up -d

# Check status
podman-compose ps
podman-compose logs -f syfter-api
```

The API will be available at http://localhost:8000

### Running on ARM Macs (Apple Silicon)

For better performance on ARM Macs, use native ARM64 containers:

```bash
cd podman

# Set platform to ARM64
export DOCKER_DEFAULT_PLATFORM=linux/arm64

# Create .env file
cat > .env << EOF
POSTGRES_PASSWORD=your_secure_password
MINIO_ROOT_USER=minio_admin
MINIO_ROOT_PASSWORD=your_minio_password
DOCKER_DEFAULT_PLATFORM=linux/arm64
EOF

# Build and start with ARM images
podman-compose build
podman-compose up -d
```

**Note**: Running x86_64 (amd64) containers under emulation on ARM Macs is significantly slower (5-10x) due to QEMU emulation overhead. Use native ARM64 images whenever possible for development.

## Manual Setup

### 1. PostgreSQL Setup

#### Install PostgreSQL

**RHEL/Fedora:**
```bash
sudo dnf install postgresql-server postgresql-contrib
sudo postgresql-setup --initdb
sudo systemctl enable --now postgresql
```

**Ubuntu/Debian:**
```bash
sudo apt install postgresql postgresql-contrib
sudo systemctl enable --now postgresql
```

#### Create Database and User

```bash
sudo -u postgres psql << EOF
CREATE USER syfter WITH PASSWORD 'your_secure_password';
CREATE DATABASE syfter OWNER syfter;
GRANT ALL PRIVILEGES ON DATABASE syfter TO syfter;
EOF
```

#### Configure Remote Access (if needed)

Edit `/var/lib/pgsql/data/postgresql.conf`:
```
listen_addresses = '*'
```

Edit `/var/lib/pgsql/data/pg_hba.conf`:
```
# Allow connections from your network
host    syfter    syfter    10.0.0.0/8    scram-sha-256
```

Restart PostgreSQL:
```bash
sudo systemctl restart postgresql
```

### 2. MinIO Setup

#### Install MinIO

**RHEL/Fedora:**
```bash
# Download binary
curl -O https://dl.min.io/server/minio/release/linux-amd64/minio
chmod +x minio
sudo mv minio /usr/local/bin/

# Create data directory
sudo mkdir -p /data/minio
sudo chown $USER:$USER /data/minio
```

#### Run MinIO

```bash
# Set credentials
export MINIO_ROOT_USER=minio_admin
export MINIO_ROOT_PASSWORD=your_minio_password

# Run MinIO
minio server /data/minio --console-address ":9001"
```

Or as a systemd service:

```bash
sudo cat > /etc/systemd/system/minio.service << EOF
[Unit]
Description=MinIO
After=network-online.target
Wants=network-online.target

[Service]
User=minio
Group=minio
Environment="MINIO_ROOT_USER=minio_admin"
Environment="MINIO_ROOT_PASSWORD=your_minio_password"
ExecStart=/usr/local/bin/minio server /data/minio --console-address ":9001"
Restart=always
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
EOF

sudo useradd -r minio
sudo chown -R minio:minio /data/minio
sudo systemctl daemon-reload
sudo systemctl enable --now minio
```

### 3. Syfter API Server

#### Install

```bash
# Install from PyPI
pip install "syfter[server]"

# Or from wheel file (offline)
pip install "syfter-0.9.0-py3-none-any.whl[server]"

# Or from source
git clone https://github.com/vdanen/syfter.git
cd syfter
pip install -e ".[server]"
```

#### Configure

Set environment variables:

```bash
export SYFTER_DB_TYPE=postgresql
export SYFTER_PG_HOST=localhost
export SYFTER_PG_PORT=5432
export SYFTER_PG_DATABASE=syfter
export SYFTER_PG_USER=syfter
export SYFTER_PG_PASSWORD=your_secure_password

export SYFTER_STORAGE_TYPE=s3
export SYFTER_S3_ENDPOINT=http://localhost:9000
export SYFTER_S3_BUCKET=syfter-sboms
export SYFTER_S3_ACCESS_KEY=minio_admin
export SYFTER_S3_SECRET_KEY=your_minio_password
export SYFTER_S3_USE_SSL=false

export SYFTER_HOST=0.0.0.0
export SYFTER_PORT=8000
export SYFTER_WORKERS=4
```

Or create a `.env` file and use something like `python-dotenv`.

#### Run

```bash
# Development mode
python -m uvicorn server.main:app --reload

# Production mode
python -m uvicorn server.main:app --host 0.0.0.0 --port 8000 --workers 4

# Or using the entry point
syfter-server
```

Or as a systemd service:

```bash
sudo cat > /etc/systemd/system/syfter-api.service << EOF
[Unit]
Description=Syfter API Server
After=network.target postgresql.service minio.service

[Service]
User=syfter
Group=syfter
WorkingDirectory=/opt/syfter
Environment="PATH=/opt/syfter/.venv/bin"
EnvironmentFile=/opt/syfter/.env
ExecStart=/opt/syfter/.venv/bin/syfter-server
Restart=always

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable --now syfter-api
```

## Client Configuration

Configure clients to use the server:

```bash
# Set server URL
export SYFTER_SERVER=http://your-server:8000

# Verify connection
syfter stats

# Run a scan
syfter scan /path/to/rpms -p rhel -v 10.0

# Query packages
syfter query -n "kernel%"

# Export SBOM
syfter export -p rhel -v 10.0 -f spdx-json -o rhel-10.spdx.json
```

## Production Considerations

### Security

1. **Use HTTPS**: Put a reverse proxy (nginx, HAProxy) in front of the API with TLS
2. **Firewall**: Restrict access to PostgreSQL and MinIO ports
3. **Authentication**: API key authentication is enabled by default. Set an initial admin key and configure OIDC if bearer-token authentication is needed; see [Server Configuration](SERVER-CONFIGURATION.md).

### Scaling

1. **API Workers**: Increase `SYFTER_WORKERS` for more concurrent requests
2. **PostgreSQL**: Consider connection pooling (pgbouncer) for 30+ clients
3. **MinIO**: Can be clustered for high availability

For large catalogs, review these PostgreSQL indexes and create any that are missing from the database:

```sql
CREATE INDEX idx_package_name_c ON packages (name COLLATE "C");
CREATE INDEX idx_package_name_pattern ON packages (name text_pattern_ops);
CREATE INDEX idx_packages_product_id ON packages (product_id);
CREATE INDEX idx_scan_product ON scans (product_id);
CREATE INDEX idx_dep_package_type ON dependencies (package_id, dependency_type);
```

### Backup

1. **PostgreSQL**: Regular pg_dump backups
2. **MinIO**: Enable versioning and replication

### Monitoring

1. **API**: Check `/health` endpoint
2. **PostgreSQL**: Monitor connections and query performance
3. **MinIO**: Monitor disk usage and request rates

## OpenShift / ROSA HCP Deployment

For deploying on OpenShift (including ROSA HCP on AWS), use the manifests in the `manifests/` directory. This provides a production-grade setup with PostgreSQL, S3 storage, Keycloak OIDC authentication, and built-in API key auth with rate limiting and response caching.

### Prerequisites

- OpenShift 4.14+ cluster with `oc` CLI configured
- AWS S3 bucket for SBOM storage
- Cluster admin access

### Configuration

Before deploying, replace placeholders in the manifest files. Search for `__` to find all values:

| Placeholder | Description | Example |
|---|---|---|
| `__CLUSTER_DOMAIN__` | OpenShift apps domain | `apps.mycluster.example.com` |
| `__OIDC_ISSUER_URL__` | Keycloak realm URL (auto-set by `setup-keycloak.sh`) | `https://keycloak-syfter.apps.example.com/realms/syfter` |
| `__S3_BUCKET__` | S3 bucket name for SBOM storage | `syfter-sboms-myorg` |

The PostgreSQL storage class defaults to `gp3-csi` (AWS). Update `manifests/postgres/statefulset.yaml` for other platforms.

### Deploy

```bash
# 1. Namespace
oc apply -f manifests/namespace.yaml

# 2. Secrets
oc -n syfter create secret generic syfter-db-credentials \
  --from-literal=POSTGRES_USER=syfter \
  --from-literal=POSTGRES_PASSWORD=$(openssl rand -hex 16) \
  --from-literal=POSTGRES_DB=syfter

oc -n syfter create secret generic syfter-admin-key \
  --from-literal=api-key=$(python3 -c "import secrets; print(secrets.token_hex(32))")

# 3. PostgreSQL
oc apply -f manifests/postgres/

# 4. Build and deploy API
oc apply -f manifests/api/buildconfig.yaml -f manifests/api/imagestream.yaml
oc -n syfter start-build syfter-api --follow
oc apply -f manifests/api/

# 5. Keycloak (browser access)
./manifests/keycloak/setup-keycloak.sh deploy

# 6. Verify
curl https://syfter-cli-syfter.__CLUSTER_DOMAIN__/health
```

See `manifests/s3/irsa-setup.sh` for IRSA configuration (recommended over static S3 credentials on AWS).

### Scanning RPM Repositories

Use `scripts/scan-repodata.py` to scan RPM repositories by parsing `repodata/primary.xml.gz`:

```bash
export SYFTER_SERVER=https://syfter-cli-syfter.__CLUSTER_DOMAIN__
export SYFTER_API_KEY=<your-key>
python3 scripts/scan-repodata.py --workers 2
```

Set `PULP_BASE_URL` to override the default RPM repository server.

For the full user setup guide, see [Getting-Started.md](Getting-Started.md).

## AWS S3 Configuration

To use AWS S3 instead of MinIO:

```bash
export SYFTER_STORAGE_TYPE=s3
export SYFTER_S3_BUCKET=your-bucket-name
export SYFTER_S3_ACCESS_KEY=your_aws_access_key
export SYFTER_S3_SECRET_KEY=your_aws_secret_key
export SYFTER_S3_REGION=us-east-1
# Don't set SYFTER_S3_ENDPOINT for AWS S3
```

## Troubleshooting

### API won't start

```bash
# Check logs
journalctl -u syfter-api -f

# Test database connection
psql -h localhost -U syfter -d syfter

# Test MinIO connection
mc alias set local http://localhost:9000 minio_admin your_password
mc ls local/
```

### Slow queries

```bash
# Check PostgreSQL indexes
psql -U syfter -d syfter -c "\di"

# Analyze tables
psql -U syfter -d syfter -c "ANALYZE;"
```

### Large SBOM upload fails

- Increase `SYFTER_TIMEOUT` on client
- Check MinIO disk space
- Check PostgreSQL connection limits
- For very large scans (e.g., RHEL with 8M+ files), use `--skip-files` to disable file indexing:
  ```bash
  syfter scan /path/to/rpms -p rhel -v 10.0 --skip-files
  ```
- Increase server memory or reduce worker count

### Large scans (Linux distributions)

Linux distribution scans (RHEL, Fedora) can have millions of files. To handle these:

1. **Skip file indexing on client** (recommended for distro scans):
   ```bash
   syfter scan /path/to/rpms -p rhel -v 10.0 --skip-files
   ```
   This reduces the packages JSON from ~300MB to ~1MB.

2. **Increase server memory**: Set container memory limit to 8GB+

3. **Server-side threshold**: The server auto-skips file indexing for scans with >100K files.
   Configure with `SYFTER_SKIP_FILE_INDEX_THRESHOLD`:
   ```yaml
   environment:
     SYFTER_SKIP_FILE_INDEX_THRESHOLD: 50000  # Skip file indexing above 50K files
   ```

**Trade-off**: File search (`syfter query -f /path/to/file`) won't work for scans without file indexing. Package search still works.
