from fastapi import APIRouter

from app.core.config import get_settings

router = APIRouter(prefix="/api", tags=["health"])


@router.get("/health")
def health_check() -> dict[str, str]:
    settings = get_settings()
    return {
        "status": "ok",
        "llm_mode": "enabled" if settings.llm_enabled else "disabled",
        "llm_base_url": settings.llm_base_url,
        "llm_model": settings.llm_model,
    }
