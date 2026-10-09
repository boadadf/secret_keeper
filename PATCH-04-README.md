# Patch 04: false-positive diagnosis, dictionary, conservative secret heuristics

Merge into repository root; replaces src/secret_keeper/request_capture.py and
 tests/unit/test_request_capture.py. Adds config/secret-keeper-policy.json.
This is a standalone replacement addon, NOT integration with an unseen rule engine.
No new dependencies or launcher changes. Restart the proxy with the same working
Git Bash mitmdump command. Existing request_log is now METADATA ONLY.

Run ./.venv/Scripts/python.exe -m pytest.
Default policy disables ONLY the synthetic canary detector, leaves secrets enabled,
and starts with an empty dictionary. This deliberately relaxes the old test rule:
canary text in history will no longer block. It does NOT prove what caused previous
blocks, nor remove that history. Restart Copilot without resuming the test session.
The old Canary test no longer should block unless canary_enabled is explicitly true.

Normal tests: hello; Explain how passwords work; Use an API key to authenticate.
Blocked test (synthetic only): password = "Synthetic-Only-42"
Do not test real credentials. Start a fresh conversation after blocked prompts.
The full outgoing context is scanned: previous secrets in history SHOULD block,
even if the newest message is harmless. Filtering to latest text would leak history.

Dictionary example: replace dictionary: [] with an array like this:
[{"id":"customer-001","values":["Northstar Manufacturing","Northstar Manufacturing GmbH"],"boundary":"whole_phrase"}]
Use fictional names for tests, real company policy only in a protected local file.
Matching: NFKC normalization, case folding, whitespace collapse, whole_phrase or
substring. Values must have >=3 normalized characters. ID must be opaque lowercase
letters/digits/hyphen/underscore; IDs are logged. Restart after every policy edit.
Set secret_keeper_policy mitmproxy option to use an outside-repository policy path.
Missing/invalid policy blocks with policy_error: do not use a broken policy as bypass.

Detectors: bounded legacy GitHub token pattern (gh[pousr]_ plus 36 alphanumerics),
AWS access key IDs (AKIA plus 16 uppercase alphanumerics), paired private-key blocks,
credential assignments and named JSON credential fields. AWS ID is not itself the
secret key: this is conservative identifier blocking. Real authenticity not checked.
Do NOT claim all API keys/tokens/passwords supported. No newer provider-token formats,
entropy blocker, bare-password detector, or binary protocol decoding included.
Only a narrow documented redaction placeholder set is exempted. Credential variables
and examples may still be false positives; reporting a match is not proof of validity.

HTTP local status is now 422 with secret_keeper_blocked body, NOT 403. This avoids
intentionally imitating authorization denial but Copilot rendering/retries unverified.
WebSocket still drops blocked outbound messages. No fabricated protocol error or
connection termination: delay fix remains pending. No guarantee of faster retries.

Audit records include rule_id, opaque dictionary entry_id, numeric structural location,
flow_id and transport only. Never body, URL, headers, JSON field names or matched value.
Do not share an existing old raw capture file. Stop proxy and archive/remove old
capture logs securely before reusing the same request_log path if metadata-only needed.

Boundary: buffered HTTP body and UTF-8 WebSocket payload only, no headers/query,
no cross-message matching or Base64 decoding. Uninspectable content blocks with a
separate rule. Header auth is neither scanned nor bypassed: body secrets still block.
Unhandled addon errors/load failures are not a hardened fail-closed security boundary.
Resource limits, policy administrator controls and WS retention remain unfinished.

Unit tests establish hook decisions. Controlled-upstream non-receipt and actual
Copilot timeout/retry UX are NOT verified. Existing unrelated repository tests may
need updates; no claim to running the entire existing project suite is made.
