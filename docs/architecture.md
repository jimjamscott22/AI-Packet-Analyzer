# Architecture Overview

## Backend

- `FastAPI` exposes upload, status, summary, findings, and flow detail endpoints.
- Uploaded PCAP files are stored under `data/uploads/`.
- SQLite stores job metadata, normalized flows, and findings.
- The analysis pipeline is:
  1. save upload
  2. create job
  3. parse packets with the parser interface
  4. group packets into flows
  5. score flows with heuristics
  6. optionally enrich top flows with the LLM provider
  7. persist results

## Frontend

- React SPA optimized for local analyst workflow.
- Upload and polling live in the main app shell.
- Findings and flow explorer are separate work surfaces.
- Flow inspector shows evidence, metadata, and optional LLM rationale.

## Extension Points

- Add a new parser under `backend/app/parsers/`.
- Add more detectors under `backend/app/detectors/`.
- Replace the in-process background task execution with a worker queue without changing API contracts.
- Add live capture ingestion as a new source without changing normalized flow output.
