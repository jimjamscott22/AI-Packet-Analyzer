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
        payload: dict[str, Any] = {
            "model": settings.llm_model,
            "temperature": 0,
            "messages": [
                {"role": "system", "content": "You classify network metadata conservatively."},
                prompt,
            ],
        }
        if settings.llm_json_mode:
            payload["response_format"] = {"type": "json_object"}

        headers: dict[str, str] = {}
        if settings.llm_api_key:
            headers["Authorization"] = f"Bearer {settings.llm_api_key}"

        started_at = time.perf_counter()
        try:
            timeout = httpx.Timeout(settings.llm_timeout_seconds, connect=2.0)
            async with httpx.AsyncClient(timeout=timeout) as client:
                response = await client.post(
                    f"{settings.llm_base_url.rstrip('/')}/chat/completions",
                    headers=headers,
                    json=payload,
                )
                response.raise_for_status()
            body = response.json()
            content = body["choices"][0]["message"]["content"]
            parsed = _parse_json_content(content)
        except Exception:
            return None

        return {
            "model": settings.llm_model,
            "prompt_version": PROMPT_VERSION,
            "classification": parsed.get("classification", "needs_review"),
            "rationale": parsed.get("rationale", "No rationale returned."),
            "confidence": float(parsed.get("confidence", 0.5)),
            "recommended_action": parsed.get("recommended_action", "Review the related metadata manually."),
            "token_count": body.get("usage", {}).get("total_tokens"),
            "latency_ms": round((time.perf_counter() - started_at) * 1000, 2),
        }


def _parse_json_content(content: str) -> dict[str, Any]:
    text = content.strip()
    try:
        parsed = json.loads(text)
    except json.JSONDecodeError:
        start = text.find("{")
        end = text.rfind("}")
        if start < 0 or end <= start:
            raise
        parsed = json.loads(text[start : end + 1])
    if not isinstance(parsed, dict):
        raise ValueError("LLM response JSON must be an object")
    return parsed
