# Local Setup

## Backend

```bash
uv --project backend sync --group dev
uv --project backend run uvicorn app.main:app --reload
```

The backend should be started from `backend/` so the `app` package resolves, or with `PYTHONPATH=backend/src`.

## Frontend

```bash
cd frontend
npm install
npm run dev
```

## LM Studio

The optional LLM review path talks to an OpenAI-compatible `/v1/chat/completions` endpoint. The default target is a local LM Studio server.

1. Start LM Studio and load a model.
2. Enable the local server (default `http://127.0.0.1:1234`).
3. Set the model identifier to the name shown in LM Studio.
4. Enable review in the backend environment:

```bash
export LLM_ENABLED=true
export LLM_BASE_URL=http://127.0.0.1:1234/v1
export LLM_MODEL=local-model
```

No API key is required for LM Studio. If the local server is down, analysis still completes in heuristics-only mode.

## Environment Variables

- `LLM_ENABLED`: optional, set to `true` to send top-scored flows to LM Studio. If unset, a non-empty `LLM_API_KEY` or `OPENAI_API_KEY` still enables review for compatibility.
- `LLM_BASE_URL`: optional, defaults to `http://127.0.0.1:1234/v1`
- `LLM_MODEL`: optional, defaults to `local-model`. Use the exact identifier shown in LM Studio.
- `LLM_API_KEY`: optional. LM Studio does not need one; send it only if your local server requires a bearer token.
- `LLM_MAX_FLOWS`: optional, defaults to `5`
- `LLM_TIMEOUT_SECONDS`: optional, defaults to `60`
- `LLM_JSON_MODE`: optional, defaults to `false`. Set `true` only if the loaded model supports `response_format=json_object`.
- `OPENAI_API_KEY`, `OPENAI_BASE_URL`, and `OPENAI_MODEL`: compatibility aliases. Prefer the `LLM_*` variables.

The dashboard health and summary views show whether review is enabled plus the configured base URL and model. They never display an API key.

## Sample Captures

Representative benign and suspicious PCAPs live in `samples/` for local upload testing:

- `benign-dns.pcap`
- `benign-tls.pcap`
- `suspicious-dns-tunnel.pcap`
- `suspicious-tls-beacon.pcap`
- `suspicious-tls-opaque.pcap`

## Limits

- Uploads are capped at 100 MB by default.
- v1 focuses on `.pcap` and `.pcapng` uploads only.
- Payloads are not persisted or surfaced in the UI.
