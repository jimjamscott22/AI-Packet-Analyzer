from dataclasses import dataclass, field
from functools import lru_cache
import os
from pathlib import Path


DEFAULT_LLM_BASE_URL = "http://127.0.0.1:1234/v1"
DEFAULT_LLM_MODEL = "local-model"


def _env(*names: str, default: str | None = None) -> str | None:
    for name in names:
        value = os.getenv(name)
        if value:
            return value
    return default


def _env_flag(name: str, default: bool = False) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _env_float(name: str, default: float) -> float:
    raw = os.getenv(name)
    if raw is None or not raw.strip():
        return default
    return float(raw)


def _env_int(name: str, default: int) -> int:
    raw = os.getenv(name)
    if raw is None or not raw.strip():
        return default
    return int(raw)


@dataclass(frozen=True)
class Settings:
    app_name: str = "AI Packet Analyzer"
    data_dir: Path = Path("data")
    upload_dir: Path = Path("data/uploads")
    db_path: Path = Path("data/packet_analyzer.db")
    max_upload_size_bytes: int = 100 * 1024 * 1024
    llm_api_key: str | None = field(default_factory=lambda: _env("LLM_API_KEY", "OPENAI_API_KEY"))
    llm_base_url: str = field(
        default_factory=lambda: _env("LLM_BASE_URL", "OPENAI_BASE_URL", default=DEFAULT_LLM_BASE_URL)
        or DEFAULT_LLM_BASE_URL
    )
    llm_model: str = field(
        default_factory=lambda: _env("LLM_MODEL", "OPENAI_MODEL", default=DEFAULT_LLM_MODEL) or DEFAULT_LLM_MODEL
    )
    llm_max_flows: int = field(default_factory=lambda: _env_int("LLM_MAX_FLOWS", 5))
    llm_timeout_seconds: float = field(default_factory=lambda: _env_float("LLM_TIMEOUT_SECONDS", 60.0))
    llm_json_mode: bool = field(default_factory=lambda: _env_flag("LLM_JSON_MODE", default=False))

    @property
    def llm_enabled(self) -> bool:
        if os.getenv("LLM_ENABLED") is not None:
            return _env_flag("LLM_ENABLED")
        return bool(self.llm_api_key)


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    settings = Settings()
    settings.data_dir.mkdir(parents=True, exist_ok=True)
    settings.upload_dir.mkdir(parents=True, exist_ok=True)
    return settings
