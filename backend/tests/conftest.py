import pytest

from app.core.config import get_settings


@pytest.fixture(autouse=True)
def isolate_llm_environment(monkeypatch):
    for name in (
        "LLM_ENABLED",
        "LLM_API_KEY",
        "LLM_BASE_URL",
        "LLM_MODEL",
        "LLM_JSON_MODE",
        "LLM_MAX_FLOWS",
        "LLM_TIMEOUT_SECONDS",
        "OPENAI_API_KEY",
        "OPENAI_BASE_URL",
        "OPENAI_MODEL",
    ):
        monkeypatch.delenv(name, raising=False)
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()
