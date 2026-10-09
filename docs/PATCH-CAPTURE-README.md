# Request capture patch 01

Copy the contents of this archive into the existing repository root.
It adds/replaces only:
- src/secret_keeper/request_capture.py
- scripts/capture-requests.cmd
- tests/unit/test_request_capture.py
- this file

It does NOT overwrite pyproject.toml, engine.py, cli.py or configuration.

## Run
1. Stop the existing proxy with Ctrl+C.
2. From CMD in the repository root: scripts\capture-requests.cmd
   From Git Bash: cmd.exe /c 'scripts\capture-requests.cmd'
   Alternatively double-click scripts/capture-requests.cmd.
3. Keep this window running. Existing Copilot proxy/CA settings remain unchanged.
4. Send a new synthetic prompt with marker SECRET_KEEPER_CAPTURE_TEST_3.
5. Search the newly appended records in:
   %LOCALAPPDATA%\SecretKeeper\logs\copilot-requests.jsonl

Expected: body_available=true and a nonzero raw_body_bytes for the prompt-bearing
POST. Null means unavailable; zero means an available but empty body.
Old records remain unchanged. The timestamp distinguishes new records.

This addon explicitly buffers request bodies and streams response bodies. The
launcher omits stream_large_bodies=0, which was an incorrect zero-byte streaming
threshold. A 10 MiB engine body-size limit bounds this diagnostic run; it can reject
large responses as well as requests. This is not a production limit policy.

Capture includes decoded bodies or raw Base64 when decoding fails. Headers and query
strings are excluded; request bodies and paths can still contain sensitive data.
Logs append without rotation. Restrict the Windows folder ACL and delete diagnostic
logs when no longer needed. Never commit or upload them. This is diagnostic capture,
not DLP enforcement: disk errors are reported and do not block forwarding.

Tests: .venv\Scripts\python.exe -m pytest
Tests use synthetic flow substitutes and do not require a live Copilot connection.

The normal engine.py may still contain stream_large_bodies=0 from the original
source. This patch deliberately leaves your edited engine untouched. Use this capture
launcher for this milestone. Correcting the normal launcher and its test belongs in
the next consolidated delivery after reviewing your current files.
