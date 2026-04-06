# Local Setup

## Backend

```bash
cd backend
python3 -m venv .venv
source .venv/bin/activate
pip install -e .[dev]
uvicorn app.main:app --reload
```

## Frontend

```bash
cd frontend
npm install
npm run dev
```

## Environment Variables

- `OPENAI_API_KEY`: optional, enables LLM review
- `OPENAI_BASE_URL`: optional, defaults to `https://api.openai.com/v1`
- `OPENAI_MODEL`: optional, defaults to `gpt-4.1-mini`
- `LLM_MAX_FLOWS`: optional, defaults to `5`

## Limits

- Uploads are capped at 100 MB by default.
- v1 focuses on `.pcap` and `.pcapng` uploads only.
- Payloads are not persisted or surfaced in the UI.
