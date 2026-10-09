# Patch 03 — fixed synthetic canary enforcement

Merge files into existing repository root, preserving paths. Replace capture addon
and capture unit tests. No launcher, configuration, engine or package changes.

Stop proxy and restart with the SAME Git Bash mitmdump command used successfully
for patch 02. Keep -s src/secret_keeper/request_capture.py and omit
stream_large_bodies=0. Enforcement is automatic when this addon is loaded.
Run ./.venv/Scripts/python.exe -m pytest.

Use a NEW synthetic Copilot session. First send a normal prompt. Then send:
Reply with exactly: SECRET_KEEPER_CONFIDENTIAL_CANARY
Expect HTTP 403 and/or outgoing WebSocket message drop, with Secret Keeper BLOCK
printed in the proxy terminal. HTTP /auto may block before the main model call:
this is not proof that the WebSocket enforcement path was exercised.

A dropped WebSocket message may leave Copilot waiting, timing out or retrying.
Cancel if it waits. No fake provider response is injected. Start a fresh session
for normal prompts afterward: history containing the marker can trigger new blocks.

Audit decision=BLOCK has no blocked body, headers, path or matched value. Allowed
payloads are still captured if request_log is enabled. Enforcement remains active
if logging is disabled; audit write failure does not undo a block.
Missing HTTP body or invalid text decoding blocks; available empty body is allowed.

Scope: fixed marker in raw body/message bytes, decoded HTTP text or one JSON parse
including nested strings/keys. No Base64 decoding, header/query inspection,
cross-message secret matching or general DLP. Some arbitrary binary HTTP content
will be rejected as uninspectable. No user-defined rule configuration yet.
Unexpected addon errors/load failures and resource limits need additional hardening.
Long-lived WebSocket memory retention and log rotation remain unresolved.

Unit tests verify hook decisions/drop calls, not network non-receipt. Controlled
upstream HTTP and WebSocket integration tests are still required before claiming
rejected application content never reaches the server. Do not test real secrets.
