# Patch 07 — opt-in outbound payload capture

Requires Patch 06 rules.py already present. Merge into repository ROOT. Replaces
request_capture.py, adds payload_capture.py and tests/unit/test_payload_capture.py.
Does not change private policy, public example, CMD launcher or blocking rules.
No new dependencies. Keep BOTH adjacent helper modules with the addon.

Capture off by default. request_log remains metadata-only. New mitmproxy options:
  capture_mode=off|full
  capture_file=<dedicated private JSONL path> (required for full)
  capture_max_payload_bytes=1048576 (1 MiB per raw/text representation)
  capture_max_file_bytes=16777216 (16 MiB file rotation limit)
  capture_backups=3 (current + 3 backups)
Options are launcher options, NOT rule-policy fields. Adding them to policy JSON
will cause a policy error. Audit path and capture path must differ.

CMD: keep your working state, policy and audit settings. Add these two options to
the mitmdump command inside your launcher ONLY when you deliberately need capture:
  --set capture_mode=full --set "capture_file=%LOCALAPPDATA%\SecretKeeper\captures\outbound.jsonl"
Stop and restart the proxy. FULL CAPTURE ACTIVE warning appears at error verbosity.
Invalid/unwritable configuration gives CAPTURE ERROR and disables capture, not rules.
Write failures warn CAPTURE WRITE FAILED; full capture is not guaranteed in that case.
Turn off with --set capture_mode=off (or remove the capture options), then restart.
Do not commit the capture-enabled launcher as the normal default.

Records: outbound attempted HTTP body and outbound WebSocket payload, including
blocked attempts. final_decision says ALLOW/BLOCK, never confirms server receipt.
Raw bytes are base64 stored; available decoded text saved too. No headers, full URL,
query, incoming messages, files outside routed payloads or bypassed traffic captured.
For HTTP, raw bytes may be compressed; body_text is what the addon inspected when
decoding succeeded. WS binary/uninspectable outgoing payloads are captured as bytes
and still blocked under existing inspection rules.

Each representation capped; raw_truncated/text_truncated explicitly flag missing
content. Capture is NOT exhaustive when a limit or failure occurs. Rotation deletes
oldest backup: rolling debugging capture, not an indefinite archive. No age expiry,
encryption at rest, redaction, cloud upload or secure-erasure feature. Existing files
larger than limits and symlinked parent directories need administrator review.
Windows access rights require proper folder ACLs; os.open mode alone is not a full
Windows permission policy. One proxy writer per capture file; multiprocess shared
writes/rotation not supported. On abrupt shutdown last record may be incomplete.
Synchronous local capture adds disk latency; it must not be used as a performance
or complete security-boundary guarantee. Logging failures do not intentionally
change enforcement. Unexpected addon exceptions/load failures still need hardening.

Tests in CMD:
  .venv\Scripts\python.exe -m pytest -q tests\unit\test_request_capture.py tests\unit\test_payload_capture.py
  scripts\test-proxy-integration.cmd
  .venv\Scripts\python.exe tests\integration\run_rule_modes.py
  scripts\test-expanded-rules.cmd
Capture helper suite executed at delivery. Existing rule/network suites must be
rerun in your repo; Windows live capture and network regressions pending.

Synthetic live checks: normal hello -> ALLOW capture; synthetic canary/credential
with enabled block -> BLOCK capture and existing local reject. Outgoing WebSocket
traffic should produce transport=websocket records when your client uses it. HTTP
alone is not evidence of a WS capture test. Never test with real secrets.

Captured payload files may contain everything you intended to protect, including
old context! Store outside repo, restrict access, remove when analysis is complete.
Metadata-only audit remains the recommended default. Generic redacted mode is NOT
implemented or claimed safe. Future LLM analysis must stay within your approved
private environment, not upload full captures to a public model automatically.
