# Patch 02 — HTTP and outbound WebSocket diagnostic capture

Merge these archive contents directly into D:\git\secret-keeper. Overwrite the
capture addon and its tests. No CLI, engine, pyproject, configuration or CA files
are replaced. No reinstall needed.

Stop the existing proxy. From Git Bash at repository root run:
    bash scripts/capture-requests.sh
Or from CMD:
    scripts\capture-requests.cmd
Both launchers are included NEW files. The shell launcher targets Git Bash on Windows.
They use the existing per-user CA and copilot-requests.jsonl log. Copilot's CMD proxy
settings stay unchanged. Do not run two listeners on port 8080.

Run unit tests: ./.venv/Scripts/python.exe -m pytest
Send synthetic prompt SECRET_KEEPER_WS_CAPTURE_TEST. Look in new records for
schema_version=2, transport=websocket, direction=client_to_server and the marker.
Client may choose HTTP instead; do not assume every prompt generates WebSocket traffic.
HTTP upgrade requests can also appear as separate HTTP records. Indices count messages
in both directions, so outgoing indices can have gaps.

WebSocket messages are reassembled by the engine. Text uses body_text; binary or
invalid UTF-8 uses body_raw_base64. Server-to-client bodies are not written. They
may still remain in engine memory. No WebSocket modification/blocking is implemented.

Diagnostic only: no rotation, no retention automation, no policy enforcement.
Capture-write failure logs an error and forwarding continues. Headers and query
strings are excluded, but bodies and paths can contain secrets. Use synthetic data,
restrict Windows ACLs and delete logs afterward. Never commit or upload raw captures.
The 10 MiB HTTP body-size limit can reject large responses too; it is NOT a verified
WebSocket memory limit. Engine retention on long-lived flows remains a release risk.

The normal engine.py is left intact. Use these capture launchers for this milestone.
Append sanitized local verification notes to docs/project-record.md.
