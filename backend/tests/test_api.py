import pytest
from fastapi.testclient import TestClient

from app import main


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setattr(main, "DB_PATH", tmp_path / "test.sqlite3")
    monkeypatch.setenv("GEMINI_API_KEY", "")
    monkeypatch.setenv("STORE_SUBMITTED_CONTENT", "false")
    main.init_db()
    with TestClient(main.app) as test_client:
        yield test_client


def test_demo_message_returns_grounded_evidence_and_redacts_history(client):
    response = client.post(
        "/api/analyze/message",
        json={"content": "URGENT: Your bank account will be suspended. Reply with your OTP."},
    )
    assert response.status_code == 200
    result = response.json()
    assert result["demo_mode"] is True
    assert result["risk_level"] in {"HIGH", "CRITICAL"}
    assert any(item["quote"] == "OTP" for item in result["evidence"])

    saved = client.get(f"/api/history/{result['id']}").json()
    assert saved["submitted_content"] == ""
    assert saved["title"] == "Message investigation"


def test_url_is_inspected_without_fetch_and_pdf_is_generated(client):
    response = client.post("/api/analyze/url", json={"url": "http://127.0.0.1:9/account/login"})
    assert response.status_code == 200
    result = response.json()
    assert result["input_type"] == "url"
    assert result["category"] == "URL structure review"
    assert result["evidence"]

    pdf = client.get(f"/api/history/{result['id']}/report.pdf")
    assert pdf.status_code == 200
    assert pdf.headers["content-type"] == "application/pdf"
    assert pdf.content.startswith(b"%PDF")


def test_history_delete_and_dashboard_stats_use_sqlite(client):
    created = client.post("/api/analyze/message", json={"content": "A simple appointment reminder."}).json()
    assert client.get("/api/dashboard/stats").json()["total"] == 1
    assert client.delete(f"/api/history/{created['id']}").json()["deleted"] is True
    assert client.delete("/api/history").json()["deleted"] == 0
    assert client.get("/api/dashboard/stats").json()["total"] == 0


def test_screenshot_upload_rejects_unsupported_media_type(client):
    response = client.post("/api/analyze/screenshot", files={"file": ("message.txt", b"not an image", "text/plain")})
    assert response.status_code == 415


def test_invalid_message_is_rejected(client):
    response = client.post("/api/analyze/message", json={"content": ""})
    assert response.status_code == 422
