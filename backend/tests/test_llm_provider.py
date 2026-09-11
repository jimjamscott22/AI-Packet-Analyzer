import asyncio
from dataclasses import replace

from app.core.config import Settings, get_settings
from app.llm.provider import OpenAICompatibleProvider


class _FakeResponse:
    def __init__(self, payload):
        self._payload = payload

    def raise_for_status(self) -> None:
        return None

    def json(self):
        return self._payload


class _FakeClient:
    def __init__(self, payload, captured):
        self._payload = payload
        self.captured = captured

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False

    async def post(self, url, headers=None, json=None):
        self.captured["url"] = url
        self.captured["headers"] = headers
        self.captured["json"] = json
        return _FakeResponse(self._payload)


def test_provider_posts_to_lm_studio_without_api_key(monkeypatch):
    settings = replace(
        Settings(),
        llm_api_key=None,
        llm_base_url="http://127.0.0.1:1234/v1",
        llm_model="local-model",
        llm_json_mode=False,
        llm_timeout_seconds=15.0,
    )
    monkeypatch.setenv("LLM_ENABLED", "true")
    monkeypatch.setattr("app.llm.provider.get_settings", lambda: settings)

    captured: dict = {}
    payload = {
        "choices": [
            {
                "message": {
                    "content": '{"classification":"needs_review","rationale":"Review SNI.","confidence":0.61,"recommended_action":"Inspect the flow."}'
                }
            }
        ],
        "usage": {"total_tokens": 42},
    }
    monkeypatch.setattr("app.llm.provider.httpx.AsyncClient", lambda timeout=None: _FakeClient(payload, captured))

    decision = asyncio.run(OpenAICompatibleProvider().classify_flow({"id": "flow-1"}))

    assert decision["classification"] == "needs_review"
    assert captured["url"] == "http://127.0.0.1:1234/v1/chat/completions"
    assert captured["headers"] == {}
    assert "response_format" not in captured["json"]
    assert captured["json"]["model"] == "local-model"


def test_provider_parses_fenced_json_and_sends_bearer_token(monkeypatch):
    settings = replace(
        Settings(),
        llm_api_key="lm-studio",
        llm_base_url="http://127.0.0.1:1234/v1/",
        llm_model="demo-model",
        llm_json_mode=True,
    )
    monkeypatch.setenv("LLM_ENABLED", "true")
    monkeypatch.setattr("app.llm.provider.get_settings", lambda: settings)

    captured: dict = {}
    payload = {
        "choices": [
            {
                "message": {
                    "content": "Here you go:\n```json\n{\"classification\":\"normal\",\"rationale\":\"Looks fine.\",\"confidence\":0.2,\"recommended_action\":\"None.\"}\n```"
                }
            }
        ]
    }
    monkeypatch.setattr("app.llm.provider.httpx.AsyncClient", lambda timeout=None: _FakeClient(payload, captured))

    decision = asyncio.run(OpenAICompatibleProvider().classify_flow({"id": "flow-2"}))

    assert decision["classification"] == "normal"
    assert captured["headers"] == {"Authorization": "Bearer lm-studio"}
    assert captured["json"]["response_format"] == {"type": "json_object"}


def test_provider_soft_fails_when_lm_studio_is_unreachable(monkeypatch):
    settings = replace(Settings(), llm_api_key=None, llm_base_url="http://127.0.0.1:1234/v1")
    monkeypatch.setenv("LLM_ENABLED", "true")
    monkeypatch.setattr("app.llm.provider.get_settings", lambda: settings)

    class _BoomClient(_FakeClient):
        async def post(self, url, headers=None, json=None):
            raise ConnectionError("lm studio down")

    monkeypatch.setattr("app.llm.provider.httpx.AsyncClient", lambda timeout=None: _BoomClient({}, {}))

    decision = asyncio.run(OpenAICompatibleProvider().classify_flow({"id": "flow-3"}))
    assert decision is None


def test_llm_enabled_without_api_key_when_flag_set(monkeypatch):
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.delenv("LLM_API_KEY", raising=False)
    monkeypatch.setenv("LLM_ENABLED", "true")
    get_settings.cache_clear()
    settings = Settings()
    assert settings.llm_enabled is True
    assert settings.llm_base_url == "http://127.0.0.1:1234/v1"
    get_settings.cache_clear()
