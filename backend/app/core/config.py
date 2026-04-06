from dataclasses import dataclass
from functools import lru_cache
import os
from pathlib import Path


@dataclass(frozen=True)
class Settings:
    app_name: str = "AI Packet Analyzer"
    data_dir: Path = Path("data")
    upload_dir: Path = Path("data/uploads")
    db_path: Path = Path("data/packet_analyzer.db")
    max_upload_size_bytes: int = 100 * 1024 * 1024
    llm_api_key: str | None = os.getenv("OPENAI_API_KEY")
    llm_base_url: str = os.getenv("OPENAI_BASE_URL", "https://api.openai.com/v1")
    llm_model: str = os.getenv("OPENAI_MODEL", "gpt-4.1-mini")
    llm_max_flows: int = int(os.getenv("LLM_MAX_FLOWS", "5"))

    @property
    def llm_enabled(self) -> bool:
        return bool(self.llm_api_key)


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    settings = Settings()
    settings.data_dir.mkdir(parents=True, exist_ok=True)
    settings.upload_dir.mkdir(parents=True, exist_ok=True)
    return settings
