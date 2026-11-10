# Syfter

[![OpenSSF Best Practices](https://www.bestpractices.dev/projects/11827/badge)](https://www.bestpractices.dev/projects/11827)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/vdanen/syfter/badge)](https://scorecard.dev/viewer/?uri=github.com/vdanen/syfter)
![GitHub release (latest SemVer)](https://img.shields.io/github/v/release/vdanen/syfter?sort=semver)
![PyPI release](https://img.shields.io/pypi/s/syfter)
![Downloads](https://static.pepy.tech/badge/syfter)

Syfter collects and manages SBOMs for software products, RPM repositories, and container images. It includes a CLI, an API server, and a web dashboard for importing, searching, tracing, and exporting software inventory.

## Features

- Import SPDX, CycloneDX, syft-json, and CSV or JSON package lists.
- Scan local targets and container images, then store and search their SBOMs.
- Search packages, files, dependencies, and component relationships across products.
- Trace packages across repositories and container layers, and analyze CVE impact with VULCAN.
- Organize scans with tags, access controls, and optional CID-tag enforcement.
- Browse product and package data in the web dashboard.

Production catalogs include more than 20 million packages and 500 million RPM dependency relationships.

## Install

Install the CLI from PyPI:

```bash
uv tool install syfter
```

Install the server components as well:

```bash
uv tool install "syfter[server]"
```

You can also install with pip:

```bash
pip install syfter
# Include server components
pip install "syfter[server]"
```

For a development install, clone the repository and see [Building Syfter](docs/BUILDING.md).

Check the installed version with `syfter --version`.

## Quick start

Point the CLI at your Syfter server and set your API key:

```bash
export SYFTER_SERVER=https://your-server.example.com
export SYFTER_API_KEY=your-api-key

syfter stats
syfter query -n "openssl%"
syfter scan /path/to/rpms -p rhel -v 10.1
syfter import sbom.cdx.json -p myproduct -v 1.0
```

Run `syfter --help` or `syfter <command> --help` for command options.

## Documentation

- [Getting started](docs/Getting-Started.md): install and use the CLI.
- [Deployment guide](docs/DEPLOYMENT.md): run the API server and configure databases and storage.
- [Server configuration](docs/SERVER-CONFIGURATION.md): environment variables and defaults.
- [API reference](docs/API-REFERENCE.md): endpoints, authentication, and interactive API docs.
- [Building and testing](docs/BUILDING.md): development setup, tests, and package builds.
- [Data flow](docs/DATAFLOW.md): how scans and SBOM data move through Syfter.

Syfter is designed for OpenShift and Kubernetes. Deployment manifests and the server container are in [`manifests/`](manifests/) and [`podman/`](podman/).

## License

Apache License 2.0
