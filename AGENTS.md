# AGENTS.md

## Project Summary

AI Packet Analyzer is a local-first network analysis application for offline PCAP and PCAPNG review. The current product shape is:

- FastAPI backend for upload, job execution, summaries, findings, flow listing, and flow detail
- SQLite persistence for jobs, normalized flows, and findings
- Scapy-based packet parsing with metadata-first protocol extraction
- Heuristics-first analysis with optional OpenAI-compatible LLM enrichment
- React frontend for upload, job polling, findings review, flow exploration, and detail inspection

The core product constraint is to preserve a practical analyst workflow without turning the app into a full packet retention or distributed processing platform.

## Current Architecture

### Backend

- `backend/app/api/routes/`
  - HTTP routes for jobs and health
- `backend/app/services/`
  - upload storage, flow building, job persistence helpers, analysis orchestration
- `backend/app/parsers/`
  - parser abstraction and Scapy implementation
- `backend/app/detectors/`
  - heuristic scoring and finding generation
- `backend/app/db/`
  - SQLite setup and connection helpers
- `backend/app/models/`
  - Pydantic transport schemas

### Frontend

- `frontend/src/App.tsx`
  - top-level job polling and dashboard state
- `frontend/src/components/`
  - upload, status, summary, findings, flow explorer, and detail inspector UI
- `frontend/src/api/client.ts`
  - typed API client for the backend

## Behavior and Constraints

- Treat the app as local-first and single-user.
- Offline upload analysis is the default operating mode.
- Do not introduce raw payload persistence in UI-visible records.
- Keep heuristic detection separate from advisory LLM output.
- Prefer additive API and schema changes over breaking contract changes.
- Persist normalized flow metadata in `metadata_json` unless a new relational field is clearly necessary.

## Recently Implemented Upgrades

The following near-term roadmap items are now implemented:

- Dashboard filtering and pagination
  - findings now support `severity`, `source`, `search`, `offset`, and `limit`
  - findings responses now return `total` plus `items`
  - flow search now matches host fields, classification, and persisted metadata text
  - flows and findings use deterministic ordering suitable for pagination
  - frontend findings and flow views now expose search, filters, counts, page state, and paging controls
- Richer TLS metadata extraction
  - TLS parsing now performs best-effort ClientHello and ServerHello inspection from visible payload bytes
  - extracted metadata includes `record_version`, `handshake_type`, `client_version`, `sni`, `alpn_protocols`, `cipher_suites_sample`, `session_id_length`, and `ja3_like_fingerprint`
  - flow normalization now rolls TLS observations up into analyst-facing metadata such as handshake visibility, ALPN union, first seen SNI, JA3-like fingerprints, and TLS record counts
- Stronger TLS evidence presentation
  - TLS heuristics now use handshake visibility, SNI, ALPN, and JA3-like patterns
  - flow detail view now renders key TLS metadata before raw JSON
- Backend query performance improvements
  - SQLite indexes were added for common flow and findings list access patterns

## Remaining Planned Upgrades

### Near-Term

- Better sample captures and integration fixtures
  - add representative benign and suspicious PCAP inputs
  - add higher-confidence end-to-end test coverage for parsing, flow generation, and findings output
- Improved anomaly ranking and evidence presentation
  - refine scoring weights across DNS, beaconing, and TLS
  - improve evidence prioritization and wording for analyst review
  - consider better finding-to-flow grouping when multiple related flows support one conclusion

### Later

- Live interface capture
- Raspberry Pi or remote sensor mode
- Multi-job queue with a dedicated worker process
- Broader protocol support
- Analyst feedback loops for heuristic tuning

## Implementation Guidance For Future Agents

- Before changing API contracts, inspect both:
  - `backend/app/models/schemas.py`
  - `frontend/src/types/api.ts`
- Before changing list behavior, inspect:
  - `backend/app/services/job_service.py`
  - `frontend/src/api/client.ts`
  - `frontend/src/App.tsx`
- Before changing protocol extraction, inspect:
  - `backend/app/parsers/scapy_parser.py`
  - `backend/app/services/flow_builder.py`
  - `backend/app/detectors/heuristics.py`
- Prefer extending existing metadata and evidence structures instead of introducing parallel representations.
- Keep parsing best-effort and non-fatal. Malformed or partial traffic should degrade metadata quality, not fail the job.
- If a roadmap item requires breaking storage or API changes, document the migration path explicitly in the PR or follow-up notes.

## Verification Expectations

Backend verification:

```bash
PYTHONPATH=backend pytest backend/tests -q
```

Frontend verification:

```bash
cd frontend
npm run build
```

If future work adds frontend tests, update this file with the expected command and scope.
