"""Unit tests for upstream work-item fixes (WI #4-7)."""

import pytest
from fastapi.testclient import TestClient


@pytest.fixture
def api_client(tmp_path, monkeypatch):
    """FastAPI TestClient with auth disabled and isolated SQLite DB."""
    db_path = tmp_path / "test.db"
    sbom_path = tmp_path / "sboms"
    monkeypatch.setenv("SYFTER_SQLITE_PATH", str(db_path))
    monkeypatch.setenv("SYFTER_STORAGE_TYPE", "local")
    monkeypatch.setenv("SYFTER_LOCAL_PATH", str(sbom_path))
    monkeypatch.setenv("SYFTER_AUTH_ENABLED", "false")

    from server.config import ServerConfig, get_config, set_config

    import server.config as config_mod

    config_mod._config = None
    set_config(ServerConfig.from_env())

    from server.db import init_db
    from server.main import app

    init_db()
    with TestClient(app) as client:
        yield client

    config_mod._config = None


class TestLayersRouteOrdering:
    """WI #4: /search/packages must not be shadowed by /{product}/{version}."""

    def test_static_routes_registered_before_parametric(self):
        from server.api.layers import router

        paths = [getattr(route, "path", None) for route in router.routes]
        assert paths.index("/search/packages") < paths.index("/{product_name}/{product_version}")
        assert paths.index("/chains") < paths.index("/{product_name}/{product_version}")


class TestProductOsidbFields:
    """WI #5: ps_update_stream and ps_module persist on create."""

    def test_create_product_persists_osidb_fields(self, api_client):
        payload = {
            "name": "rhel",
            "version": "9.6-test",
            "ps_update_stream": "rhel-9.6.z",
            "ps_module": "rhel-9",
        }
        create = api_client.post("/api/v1/products/", json=payload)
        assert create.status_code == 201
        body = create.json()
        assert body["ps_update_stream"] == "rhel-9.6.z"
        assert body["ps_module"] == "rhel-9"

        get = api_client.get("/api/v1/products/rhel/9.6-test")
        assert get.status_code == 200
        assert get.json()["ps_update_stream"] == "rhel-9.6.z"
        assert get.json()["ps_module"] == "rhel-9"


class TestQueryValidation:
    """WI #6: negative limit/offset return 422, not 500."""

    def test_negative_limit_rejected(self, api_client):
        response = api_client.get("/api/v1/query/packages?limit=-1")
        assert response.status_code == 422

    def test_negative_offset_rejected(self, api_client):
        response = api_client.get("/api/v1/query/packages?offset=-1")
        assert response.status_code == 422


class TestS3EndpointNormalization:
    """WI #7: bare hostnames get https:// prefix."""

    def test_normalize_bare_hostname(self):
        from server.storage.s3 import normalize_s3_endpoint

        assert normalize_s3_endpoint("s3-us-east-1.amazonaws.com") == (
            "https://s3-us-east-1.amazonaws.com"
        )

    def test_preserve_existing_scheme(self):
        from server.storage.s3 import normalize_s3_endpoint

        assert normalize_s3_endpoint("https://minio.example.com") == "https://minio.example.com"
        assert normalize_s3_endpoint("http://minio.example.com") == "http://minio.example.com"

    def test_empty_values(self):
        from server.storage.s3 import normalize_s3_endpoint

        assert normalize_s3_endpoint(None) is None
        assert normalize_s3_endpoint("") is None
        assert normalize_s3_endpoint("  ") is None
