# Architecture Overview

## Backend

- `FastAPI` exposes upload, status, summary, findings, flow detail, and health endpoints.
- Uploaded PCAP files are stored under `data/uploads/`.
- SQLite stores job metadata, normalized flows, and findings.
- Application code lives under `backend/src/app/`.
- The analysis pipeline is:
  1. save upload
  2. create job
  3. parse packets with the parser interface
  4. group packets into flows
  5. score flows with heuristics
  6. optionally enrich top flows with the LM Studio / OpenAI-compatible provider
  7. persist results

LLM enrichment is advisory. Heuristic findings stay tagged `source=heuristic`; LLM escalations are tagged `source=llm` and stored on the flow as `llm_json`. A down or incompatible local model fails soft and leaves heuristic results intact.

## Frontend

- React SPA optimized for local analyst workflow.
- Upload and polling live in the main app shell.
- Findings and flow explorer are separate work surfaces.
- Findings can be selected to open a related flow in the inspector.
- Flow inspector shows prioritized evidence, TLS metadata, raw metadata, and optional LLM rationale.
- Overview shows LM Studio connection status from `/api/health` and job summary fields: enabled flag, base URL, and model.

## Extension Points

- Add a new parser under `backend/src/app/parsers/`.
- Add more detectors under `backend/src/app/detectors/`.
- Replace the in-process background task execution with a worker queue without changing API contracts.
- Add live capture ingestion as a new source without changing normalized flow output.
- Point `LLM_BASE_URL` at any OpenAI-compatible server if you are not using LM Studio.
