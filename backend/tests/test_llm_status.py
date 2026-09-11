from dataclasses import replace

from fastapi.testclient import TestClient

from app.core.config import Settings
from app.db import database
from app.main import app
from app.services.job_service import create_job, get_summary, replace_job_results


def test_health_reports_lm_studio_status(monkeypatch):
    settings = replace(
        Settings(),
        llm_api_key=None,
        llm_base_url="http://127.0.0.1:1234/v1",
        llm_model="local-model",
    )
    monkeypatch.setenv("LLM_ENABLED", "true")
    monkeypatch.setattr("app.api.routes.health.get_settings", lambda: settings)

    response = TestClient(app).get("/api/health")
    assert response.status_code == 200
    payload = response.json()
    assert payload["status"] == "ok"
    assert payload["llm_mode"] == "enabled"
    assert payload["llm_base_url"] == "http://127.0.0.1:1234/v1"
    assert payload["llm_model"] == "local-model"


def test_summary_includes_llm_connection_fields(tmp_path, monkeypatch):
    settings = replace(
        Settings(),
        data_dir=tmp_path,
        upload_dir=tmp_path / "uploads",
        db_path=tmp_path / "packet_analyzer.db",
        llm_api_key=None,
        llm_base_url="http://127.0.0.1:1234/v1",
        llm_model="local-model",
    )
    settings.upload_dir.mkdir(parents=True, exist_ok=True)
    monkeypatch.setenv("LLM_ENABLED", "false")
    monkeypatch.setattr(database, "get_settings", lambda: settings)
    monkeypatch.setattr("app.services.job_service.get_settings", lambda: settings)
    database.init_db()

    job = create_job("sample.pcap", str(tmp_path / "sample.pcap"))
    replace_job_results(job.id, [], [])
    summary = get_summary(job.id)

    assert summary.llm_enabled is False
    assert summary.llm_base_url == "http://127.0.0.1:1234/v1"
    assert summary.llm_model == "local-model"
