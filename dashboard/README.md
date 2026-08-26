# PatchProof Dashboard

Thin live-status UI for PatchProof harness runs.

## Features

- **Scenario cards**: real-time status (exploitable / not affected / tests pass / tests fail)
- **Live event log**: SSE-streamed harness events (tool calls, sandbox activity, verdicts)
- **Approval queue**: pending staging deploy approvals
- **Connection indicator**: green/red dot for SSE connection status

## Quickstart

```bash
cd dashboard
pip install -r requirements.txt
uvicorn app:app --port 8080
# Open http://localhost:8080
```

## Architecture

- **Backend**: FastAPI with Server-Sent Events (SSE) for real-time updates
- **Frontend**: Vanilla JS single-page app (no framework dependencies)
- **Data source**: Reads scenario directories (`scenarios/*/`) for verdicts, test gates, assessments
- **Streaming**: Polls every 2s, pushes state via SSE

## API Endpoints

| Endpoint | Description |
|---|---|
| `GET /` | Dashboard UI |
| `GET /api/scenarios` | All scenario statuses |
| `GET /api/events` | Recent harness events |
| `GET /api/approvals` | Pending approval queue |
| `GET /api/stream` | SSE event stream |
