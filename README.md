# AI Packet Analyzer

AI Packet Analyzer is a local-first network analysis workspace that ingests PCAP files, normalizes traffic into flows, scores suspicious behavior with heuristics, and optionally enriches the most interesting flows with an LLM review.

## What ships in v1

- FastAPI backend with asynchronous job execution
- SQLite persistence for jobs, findings, and normalized flows
- Scapy-backed PCAP parser abstraction
- Heuristic scoring for DNS tunneling, beaconing, and suspicious TLS patterns
- Optional OpenAI-compatible LLM enrichment
- React analyst dashboard for upload, polling, findings, flow exploration, and inspection

## Repository Layout

- `backend/`: API, analysis pipeline, parser, detector, and tests
- `frontend/`: React SPA for the analyst dashboard
- `docs/`: setup, architecture, and roadmap notes

## Run Locally

Backend:

```bash
cd backend
python3 -m venv .venv
source .venv/bin/activate
pip install -e .[dev]
uvicorn app.main:app --reload
```

Frontend:

```bash
cd frontend
npm install
npm run dev
```

By default the frontend expects the backend at `http://localhost:8000/api`.
