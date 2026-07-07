from __future__ import annotations

import json
import time
from typing import Any

import httpx

from app.core.config import get_settings


PROMPT_VERSION = "v1"


class LLMProvider:
    async def classify_flow(self, flow: dict[str, Any]) -> dict[str, Any] | None:
        raise NotImplementedError


class OpenAICompatibleProvider(LLMProvider):
    async def classify_flow(self, flow: dict[str, Any]) -> dict[str, Any] | None:
        settings = get_settings()
        if not settings.llm_enabled:
            return None

        prompt = {
            "role": "user",
            "content": (
                "You are reviewing normalized network flow metadata. "
                "Return JSON with keys classification, rationale, confidence, recommended_action. "
                "Choose one classification from: normal, suspicious_dns_tunneling, suspicious_beaconing, "
                "suspicious_tls_pattern, needs_review.\n\n"
                f"Flow:\n{json.dumps(flow, indent=2, sort_keys=True)}"
            ),
        }
        started_at = time.perf_counter()
        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.post(
                f"{settings.llm_base_url.rstrip('/')}/chat/completions",
                headers={"Authorization": f"Bearer {settings.llm_api_key}"},
                json={
                    "model": settings.llm_model,
                    "messages": [
                        {"role": "system", "content": "You classify network metadata conservatively."},
                        prompt,
                    ],
                    "response_format": {"type": "json_object"},
                },
            )
            response.raise_for_status()

        payload = response.json()
        content = payload["choices"][0]["message"]["content"]
        parsed = json.loads(content)
        return {
            "model": settings.llm_model,
            "prompt_version": PROMPT_VERSION,
            "classification": parsed.get("classification", "needs_review"),
            "rationale": parsed.get("rationale", "No rationale returned."),
            "confidence": float(parsed.get("confidence", 0.5)),
            "recommended_action": parsed.get("recommended_action", "Review the related metadata manually."),
            "token_count": payload.get("usage", {}).get("total_tokens"),
            "latency_ms": round((time.perf_counter() - started_at) * 1000, 2),
        }
