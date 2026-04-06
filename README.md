# AI Packet Analyzer

AI Packet Analyzer is a local-first network analysis application that combines protocol-aware packet inspection with optional LLM-assisted triage. It is designed as a practical analyst workspace for reviewing uploaded PCAP files, extracting flows, scoring suspicious behavior, and surfacing the results in a browser dashboard.

The project is inspired by tools like Wireshark and Zeek, but the goal here is narrower: turn raw packet captures into a more approachable workflow for identifying patterns like DNS tunneling, command-and-control beaconing, suspicious TLS behavior, and clearly benign traffic.

## Overview

The v1 workflow is intentionally simple:

1. Upload a `.pcap` or `.pcapng` file in the web UI.
2. The backend creates an analysis job and parses the capture asynchronously.
3. Parsed packets are grouped into normalized flows.
4. Heuristics score the flows for suspicious characteristics.
5. If configured, the top anomalous flows are sent to an OpenAI-compatible LLM for a second-pass review.
6. The UI presents job status, summary metrics, findings, flow explorer data, and per-flow detail.

This is a local MVP. It is built for offline PCAP ingestion first, not live packet capture, distributed deployment, or multi-user operation.

## What Ships In v1

- FastAPI backend with asynchronous analysis jobs
- SQLite persistence for jobs, findings, and normalized flow summaries
- Scapy-based parser abstraction for PCAP and PCAPNG ingestion
- Flow normalization for DNS, HTTP metadata, TLS metadata, and general transport traffic
- Heuristic detection for:
  - possible DNS tunneling
  - possible beaconing / callback behavior
  - suspicious TLS session patterns
- Optional OpenAI-compatible LLM enrichment for the most suspicious flows
- React dashboard for:
  - file upload
  - job polling and status updates
  - protocol and host summary views
  - findings review
  - flow exploration
  - detailed flow inspection

## Goals

- Make packet captures easier to review at the flow level.
- Preserve a clean separation between deterministic detection and advisory LLM classification.
- Keep the initial stack lightweight enough to run locally.
- Leave extension points for future live capture, sensor deployment, and richer protocol analysis.

## Non-Goals For v1

- Live network interface capture
- Raspberry Pi sensor deployment
- Multi-user accounts or authentication
- Distributed workers or queue infrastructure
- Full packet payload analysis and retention
- Full parity with Wireshark, Zeek, or Suricata

## Architecture

### Backend

The backend is built with FastAPI and split into a few small responsibilities:

- `api/`: HTTP endpoints for jobs, summaries, findings, and flow detail
- `services/`: upload handling, job lifecycle, flow building, and analysis orchestration
- `parsers/`: packet parser abstraction and the current Scapy implementation
- `detectors/`: heuristic scoring logic
- `llm/`: optional OpenAI-compatible provider integration
- `db/`: SQLite initialization and access helpers
- `models/`: transport schemas returned by the API

### Analysis Pipeline

Each analysis job follows this sequence:

1. Validate and store the uploaded capture under `data/uploads/`
2. Create a persisted job record in SQLite
3. Parse the capture into packet-level records
4. Group packets into flow-level summaries
5. Run heuristic scoring and generate findings
6. Optionally send top suspicious flows to an LLM for enrichment
7. Persist flows and findings for the frontend to query

### Frontend

The frontend is a React single-page application focused on analyst utility rather than marketing presentation. The interface centers on:

- a drag-and-drop upload panel
- a status strip for job state and progress
- summary panels for protocols and top talkers
- a findings table for suspicious patterns
- a flow explorer with filtering
- a detail inspector for evidence and metadata

## Detection Model

The application uses heuristics first and LLM review second.

### Heuristic Findings

The current detector looks for signals including:

- DNS tunneling indicators
  - high DNS query volume
  - long query names
  - high-entropy labels
  - repeated TXT queries
  - many unique subdomains
- Beaconing indicators
  - periodic connection timing
  - short repetitive sessions
  - small regular packet sizes
- TLS suspicion indicators
  - short TLS sessions
  - limited visible metadata
  - repeated opaque sessions on expected TLS ports

### LLM Role

The LLM is advisory only. It does not replace the heuristic detector and it does not inspect raw payloads. The backend sends structured flow summaries, not full packet contents.

If no API key is configured, the application still works in heuristics-only mode.

## Supported Outputs

The current result labels include:

- `normal`
- `suspicious_dns_tunneling`
- `suspicious_beaconing`
- `suspicious_tls_pattern`
- `needs_review`
- `processing_error`

## API Summary

The backend exposes the following API endpoints:

- `POST /api/jobs`
  - upload a `.pcap` or `.pcapng` file
- `GET /api/jobs/{job_id}`
  - retrieve job status, timing, progress, and error information
- `GET /api/jobs/{job_id}/summary`
  - retrieve protocol counts, host metrics, and severity totals
- `GET /api/jobs/{job_id}/findings`
  - retrieve the findings list for a completed job
- `GET /api/jobs/{job_id}/flows`
  - retrieve normalized flows with optional filtering
- `GET /api/jobs/{job_id}/flows/{flow_id}`
  - retrieve a detailed flow record including evidence and LLM rationale
- `GET /api/health`
  - service health and LLM mode status

## Repository Layout

- `backend/`
  - FastAPI app, analysis pipeline, persistence, parser abstraction, detectors, and tests
- `frontend/`
  - React SPA, API client, dashboard components, and styles
- `docs/`
  - setup notes, architecture overview, and roadmap
- `data/`
  - local upload and SQLite storage directory created at runtime

## Local Development

### Backend

```bash
cd backend
python3 -m venv .venv
source .venv/bin/activate
pip install -e .[dev]
uvicorn app.main:app --reload
```

The backend runs on `http://localhost:8000` by default.

### Frontend

```bash
cd frontend
npm install
npm run dev
```

The frontend runs on `http://localhost:5173` by default.

By default, the frontend expects the backend API at `http://localhost:8000/api`.

## Configuration

These environment variables are currently supported:

- `OPENAI_API_KEY`
  - enables optional LLM review
- `OPENAI_BASE_URL`
  - defaults to `https://api.openai.com/v1`
- `OPENAI_MODEL`
  - defaults to `gpt-4.1-mini`
- `LLM_MAX_FLOWS`
  - limits how many suspicious flows are sent to the LLM

Operational defaults:

- upload limit: `100 MB`
- storage: local disk for uploads, SQLite for metadata and findings
- parsing mode: offline PCAP upload only
- payload handling: metadata-first, no raw payload persistence in the UI

## Testing

The repository includes backend tests for:

- upload validation
- flow grouping
- heuristic detection behavior

Run them from the repo root after installing backend dev dependencies:

```bash
pytest backend/tests -q
```

## Documentation

Additional project notes live in:

- [docs/setup.md](/home/jimjamscozz22/Desktop/GitHub/repo/AI-Packet-Analyzer/docs/setup.md)
- [docs/architecture.md](/home/jimjamscozz22/Desktop/GitHub/repo/AI-Packet-Analyzer/docs/architecture.md)
- [docs/roadmap.md](/home/jimjamscozz22/Desktop/GitHub/repo/AI-Packet-Analyzer/docs/roadmap.md)

## Roadmap

Near-term extensions:

- better sample captures and integration fixtures
- richer TLS metadata extraction
- stronger filtering and pagination in the dashboard
- improved anomaly ranking and evidence presentation

Longer-term extensions:

- live capture support
- Raspberry Pi or remote sensor mode
- dedicated worker queue
- broader protocol support
- analyst feedback loops for tuning detections

## Current Status

This repository is structured as a working MVP foundation. The architecture is intended to stay simple enough for local development while leaving clear extension points for future packet sources, additional detectors, and more mature operational behavior.
