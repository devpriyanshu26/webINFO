import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest
from app import create_app


@pytest.fixture
def app():
    application = create_app("default")
    application.config["TESTING"] = True
    return application

@pytest.fixture
def client(app):
    return app.test_client()


class TestAPI:
    def test_index(self, client):
        rv = client.get("/")
        assert rv.status_code == 200

    def test_dashboard(self, client):
        rv = client.get("/dashboard")
        assert rv.status_code == 200

    def test_analyze_no_url(self, client):
        rv = client.get("/api/analyze")
        assert rv.status_code == 400
        assert b"URL" in rv.data or b"required" in rv.data

    def test_analyze_invalid_url(self, client):
        rv = client.get("/api/analyze?url=")
        assert rv.status_code == 400

    def test_analyze_valid(self, client):
        rv = client.get("/api/analyze?url=example.com")
        assert rv.status_code == 200
        data = rv.get_json()
        assert data is not None
        assert "hostname" in data
        assert "security_score" in data
        assert "vulnerabilities" in data

    def test_auth_generate_key(self, client):
        rv = client.post("/api/auth/generate")
        assert rv.status_code == 200
        data = rv.get_json()
        assert data is not None
        assert "api_key" in data

    def test_report_generate_invalid(self, client):
        rv = client.post("/api/report/generate", json={})
        assert rv.status_code == 400

    def test_rate_limiting(self, client):
        for _ in range(5):
            client.get("/api/analyze?url=example.com")
        rv = client.get("/api/analyze?url=example.com")
        assert rv.status_code in (200, 429)
