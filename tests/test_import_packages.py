"""
Tests for package-list import and ecosystem query features:
- Package-list import endpoint (JSON and CSV)
- Ecosystem (purl_type) query filter
- Product-scoped package queries
"""

import gzip
import io
import json
import os
import sqlite3
import tempfile

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import event

from server.config import ServerConfig, DatabaseConfig, StorageConfig, set_config
from server.db.session import reset_engine


def _register_sqlite_collation(dbapi_conn, connection_record):
    """Register PostgreSQL-compatible collation for SQLite."""
    if isinstance(dbapi_conn, sqlite3.Connection):
        dbapi_conn.create_collation("C", lambda a, b: (a > b) - (a < b))


@pytest.fixture(autouse=True)
def setup_test_env(tmp_path):
    """Configure SQLite + local storage for each test, disable auth."""
    db_path = tmp_path / "test.db"
    storage_path = tmp_path / "sboms"
    storage_path.mkdir()

    config = ServerConfig(
        auth_enabled=False,
        rate_limit_enabled=False,
        cache_enabled=False,
        database=DatabaseConfig(type="sqlite", sqlite_path=db_path),
        storage=StorageConfig(type="local", local_path=storage_path),
    )
    set_config(config)
    reset_engine()

    from server.db.session import get_engine
    engine = get_engine()
    event.listen(engine, "connect", _register_sqlite_collation)

    from server.db import init_db
    init_db()

    yield

    reset_engine()
    set_config(None)


@pytest.fixture
def api():
    from server.main import app
    return TestClient(app)


# ── Import-packages endpoint ──────────────────────────────────────────────


class TestImportPackages:

    def test_import_json_array(self, api):
        packages = [
            {"name": "openssl", "version": "3.0.7", "arch": "x86_64", "purl": "pkg:rpm/redhat/openssl@3.0.7"},
            {"name": "zlib", "version": "1.2.13", "purl": "pkg:rpm/redhat/zlib@1.2.13"},
        ]
        resp = api.post(
            "/api/v1/scans/import-packages",
            data={"product_name": "CID-239482", "product_version": "latest"},
            files={"packages": ("packages.json", json.dumps(packages).encode(), "application/json")},
        )
        assert resp.status_code == 201
        body = resp.json()
        assert body["product_name"] == "CID-239482"
        assert body["product_version"] == "latest"
        assert body["package_count"] == 2
        assert body["source_type"] == "package-list"

    def test_import_csv(self, api):
        csv_content = "name,version,arch,purl\nopenssl,3.0.7,x86_64,pkg:rpm/redhat/openssl@3.0.7\nspring-boot,1.3,,pkg:maven/org.springframework.boot/spring-boot@1.3\n"
        resp = api.post(
            "/api/v1/scans/import-packages",
            data={"product_name": "CID-090234", "product_version": "latest"},
            files={"packages": ("packages.csv", csv_content.encode(), "text/csv")},
        )
        assert resp.status_code == 201
        assert resp.json()["package_count"] == 2

    def test_import_gzip_json(self, api):
        packages = [{"name": "curl", "version": "8.5.0"}]
        compressed = gzip.compress(json.dumps(packages).encode())
        resp = api.post(
            "/api/v1/scans/import-packages",
            data={"product_name": "CID-849341", "product_version": "latest"},
            files={"packages": ("packages.json.gz", compressed, "application/gzip")},
        )
        assert resp.status_code == 201
        assert resp.json()["package_count"] == 1

    def test_import_replaces_existing(self, api):
        pkgs1 = [{"name": "openssl", "version": "3.0.7"}]
        api.post(
            "/api/v1/scans/import-packages",
            data={"product_name": "CID-111111", "product_version": "latest"},
            files={"packages": ("p.json", json.dumps(pkgs1).encode(), "application/json")},
        )

        pkgs2 = [{"name": "curl", "version": "8.5.0"}, {"name": "zlib", "version": "1.2.13"}]
        resp = api.post(
            "/api/v1/scans/import-packages",
            data={"product_name": "CID-111111", "product_version": "latest"},
            files={"packages": ("p.json", json.dumps(pkgs2).encode(), "application/json")},
        )
        assert resp.status_code == 201
        assert resp.json()["package_count"] == 2

        # Verify old packages are gone
        query_resp = api.get("/api/v1/query/packages", params={"product_name": "CID-111111", "name": "openssl"})
        assert query_resp.status_code == 200
        assert len(query_resp.json()) == 0

    def test_import_empty_file_fails(self, api):
        resp = api.post(
            "/api/v1/scans/import-packages",
            data={"product_name": "CID-000000", "product_version": "latest"},
            files={"packages": ("empty.json", b"", "application/json")},
        )
        assert resp.status_code == 400

    def test_import_missing_name_fails(self, api):
        packages = [{"version": "1.0"}]
        resp = api.post(
            "/api/v1/scans/import-packages",
            data={"product_name": "CID-000000", "product_version": "latest"},
            files={"packages": ("p.json", json.dumps(packages).encode(), "application/json")},
        )
        assert resp.status_code == 400
        assert "name" in resp.json()["detail"]


# ── Ecosystem (purl_type) filter ──────────────────────────────────────────


class TestPurlTypeFilter:

    @pytest.fixture(autouse=True)
    def seed_packages(self, api):
        """Seed two customers with mixed ecosystems."""
        cid1_pkgs = [
            {"name": "openssl", "version": "3.0.7", "purl": "pkg:rpm/redhat/openssl@3.0.7"},
            {"name": "spring-boot", "version": "1.3", "purl": "pkg:maven/org.springframework.boot/spring-boot@1.3"},
        ]
        cid2_pkgs = [
            {"name": "spring-boot", "version": "1.4", "purl": "pkg:maven/org.springframework.boot/spring-boot@1.4"},
            {"name": "requests", "version": "2.31.0", "purl": "pkg:pypi/requests@2.31.0"},
        ]
        api.post(
            "/api/v1/scans/import-packages",
            data={"product_name": "CID-100001", "product_version": "latest"},
            files={"packages": ("p.json", json.dumps(cid1_pkgs).encode(), "application/json")},
        )
        api.post(
            "/api/v1/scans/import-packages",
            data={"product_name": "CID-100002", "product_version": "latest"},
            files={"packages": ("p.json", json.dumps(cid2_pkgs).encode(), "application/json")},
        )

    def test_filter_maven_packages(self, api):
        resp = api.get("/api/v1/query/packages", params={"purl_type": "maven", "name": "%"})
        assert resp.status_code == 200
        results = resp.json()
        assert len(results) == 2
        assert all("maven" in r["purl"] for r in results)

    def test_filter_rpm_packages(self, api):
        resp = api.get("/api/v1/query/packages", params={"purl_type": "rpm", "name": "%"})
        assert resp.status_code == 200
        results = resp.json()
        assert len(results) == 1
        assert results[0]["name"] == "openssl"

    def test_filter_pypi_packages(self, api):
        resp = api.get("/api/v1/query/packages", params={"purl_type": "pypi", "name": "%"})
        assert resp.status_code == 200
        results = resp.json()
        assert len(results) == 1
        assert results[0]["name"] == "requests"

    @pytest.mark.skipif(True, reason="array_agg requires PostgreSQL")
    def test_frequency_with_purl_type(self, api):
        resp = api.get("/api/v1/query/packages/frequency", params={"name": "spring-boot", "purl_type": "maven"})
        assert resp.status_code == 200
        results = resp.json()
        assert len(results) == 2
        versions = {r["version"] for r in results}
        assert versions == {"1.3", "1.4"}

    def test_no_filter_returns_all(self, api):
        resp = api.get("/api/v1/query/packages", params={"name": "%"})
        assert resp.status_code == 200
        assert len(resp.json()) == 4


# ── Customer ID as product_name pattern ───────────────────────────────────


class TestCustomerIdPattern:

    @pytest.fixture(autouse=True)
    def seed_customers(self, api):
        api.post(
            "/api/v1/scans/import-packages",
            data={"product_name": "CID-200001", "product_version": "latest"},
            files={"packages": ("p.json", json.dumps([
                {"name": "openssl", "version": "3.0.7", "purl": "pkg:rpm/redhat/openssl@3.0.7"},
            ]).encode(), "application/json")},
        )
        api.post(
            "/api/v1/scans/import-packages",
            data={"product_name": "CID-200002", "product_version": "latest"},
            files={"packages": ("p.json", json.dumps([
                {"name": "openssl", "version": "3.0.7", "purl": "pkg:rpm/redhat/openssl@3.0.7"},
                {"name": "openssl", "version": "3.1.0", "purl": "pkg:rpm/redhat/openssl@3.1.0"},
            ]).encode(), "application/json")},
        )

    @pytest.mark.skipif(True, reason="array_agg requires PostgreSQL")
    def test_frequency_returns_customer_ids(self, api):
        resp = api.get("/api/v1/query/packages/frequency", params={"name": "openssl"})
        assert resp.status_code == 200
        results = resp.json()
        by_version = {r["version"]: r for r in results}
        assert "3.0.7" in by_version
        assert set(by_version["3.0.7"]["products"]) == {"CID-200001", "CID-200002"}
        assert "3.1.0" in by_version
        assert by_version["3.1.0"]["products"] == ["CID-200002"]

    def test_query_by_customer_id(self, api):
        resp = api.get("/api/v1/query/packages", params={"product_name": "CID-200001", "name": "%"})
        assert resp.status_code == 200
        results = resp.json()
        assert len(results) == 1
        assert results[0]["name"] == "openssl"
        assert results[0]["product_name"] == "CID-200001"

    def test_list_customer_packages(self, api):
        resp = api.get("/api/v1/query/list/packages/CID-200002/latest")
        assert resp.status_code == 200
        results = resp.json()
        assert len(results) == 2


# ── Tag-based query after import ─────────────────────────────────────────


class TestTagQueryAfterImport:

    def test_import_with_tags_then_query_by_tag(self, api):
        """Reproduce: import-packages with tags, then query packages by tag."""
        packages = [
            {"name": "requests", "version": "2.31.0", "purl": "pkg:pypi/requests@2.31.0"},
        ]
        upload_resp = api.post(
            "/api/v1/scans/import-packages",
            data={
                "product_name": "CID-TEST",
                "product_version": "2026-08-17",
                "source_type": "package-list",
                "tags": "CID-TEST,2026-08-17",
            },
            files={"packages": ("packages.json", json.dumps(packages).encode(), "application/json")},
        )
        assert upload_resp.status_code == 201
        body = upload_resp.json()
        assert body["package_count"] == 1
        assert "CID-TEST" in body["tags"], f"Tags not saved: {body['tags']}"

        query_resp = api.get("/api/v1/query/packages", params={"tag": "CID-TEST", "name": "%", "limit": 10})
        assert query_resp.status_code == 200
        results = query_resp.json()
        assert len(results) == 1, f"Expected 1 package, got {len(results)}: {results}"
        assert results[0]["name"] == "requests"

    def test_import_with_multiple_tags_query_each(self, api):
        """Verify both tags work for querying."""
        packages = [{"name": "flask", "version": "3.0.0"}]
        upload_resp = api.post(
            "/api/v1/scans/import-packages",
            data={
                "product_name": "CID-MULTI",
                "product_version": "latest",
                "tags": "CID-MULTI,team-alpha",
            },
            files={"packages": ("p.json", json.dumps(packages).encode(), "application/json")},
        )
        assert upload_resp.status_code == 201
        assert set(upload_resp.json()["tags"]) == {"CID-MULTI", "team-alpha"}

        for tag_name in ["CID-MULTI", "team-alpha"]:
            resp = api.get("/api/v1/query/packages", params={"tag": tag_name, "name": "%"})
            assert resp.status_code == 200
            assert len(resp.json()) == 1, f"Tag '{tag_name}' query returned {len(resp.json())} results"


# ── CID tag enforcement ─────────────────────────────────────────────────


class TestCidTagEnforcement:

    @pytest.fixture(autouse=True)
    def enable_enforcement(self):
        from server.config import get_config
        config = get_config()
        original = config.require_cid_tag
        config.require_cid_tag = True
        yield
        config.require_cid_tag = original

    def _packages_file(self):
        data = json.dumps([{"name": "openssl", "version": "3.0.7"}]).encode()
        return ("packages.json", data, "application/json")

    def test_rejected_without_tags(self, api):
        resp = api.post(
            "/api/v1/scans/import-packages",
            data={"product_name": "CID-300001", "product_version": "latest"},
            files={"packages": self._packages_file()},
        )
        assert resp.status_code == 400
        assert "CID-" in resp.json()["detail"]

    def test_rejected_with_non_cid_tags(self, api):
        resp = api.post(
            "/api/v1/scans/import-packages",
            data={"product_name": "CID-300001", "product_version": "latest", "tags": "team-a,prod"},
            files={"packages": self._packages_file()},
        )
        assert resp.status_code == 400
        assert "CID-" in resp.json()["detail"]

    def test_accepted_with_cid_tag(self, api):
        resp = api.post(
            "/api/v1/scans/import-packages",
            data={"product_name": "CID-300001", "product_version": "latest", "tags": "CID-300001"},
            files={"packages": self._packages_file()},
        )
        assert resp.status_code == 201
        assert "CID-300001" in resp.json()["tags"]

    def test_accepted_with_mixed_tags(self, api):
        resp = api.post(
            "/api/v1/scans/import-packages",
            data={"product_name": "CID-300002", "product_version": "latest", "tags": "team-a,CID-300002"},
            files={"packages": self._packages_file()},
        )
        assert resp.status_code == 201
        assert "CID-300002" in resp.json()["tags"]

    def test_rejected_with_lowercase_cid(self, api):
        resp = api.post(
            "/api/v1/scans/import-packages",
            data={"product_name": "CID-300003", "product_version": "latest", "tags": "cid-300003"},
            files={"packages": self._packages_file()},
        )
        assert resp.status_code == 400

    def test_enforcement_off_allows_no_tags(self):
        from server.config import get_config
        get_config().require_cid_tag = False
        from server.main import app
        client = TestClient(app)
        resp = client.post(
            "/api/v1/scans/import-packages",
            data={"product_name": "CID-300004", "product_version": "latest"},
            files={"packages": self._packages_file()},
        )
        assert resp.status_code == 201
