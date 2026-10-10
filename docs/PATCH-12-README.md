# Patch 12: Verified previous-answer credential exemption

Apply to your existing checkout after Patches 09, 10 and 11.
This archive adds a provenance helper, a guarded installer and tests.
It does NOT contain replacement versions of rules.py, payload_capture.py or
request_capture.py. The installer edits narrowly defined addon fragments and backs
up request_capture.py, preserving prior patch behavior. Unexpected layouts stop
without writing changes.

## Install with Windows CMD

Stop the proxy first. Extract at D:\git\secret-keeper preserving folders.

```bat
cd /d D:\git\secret-keeper
.venv\Scripts\python.exe scripts\apply-patch-12.py
.venv\Scripts\python.exe -m pytest tests\unit -q
set "SECRET_KEEPER_CONSOLE_CAPTURE=true"
set "SECRET_KEEPER_CAPTURE_MODE=off"
scripts\capture-requests.cmd
```

Restart Copilot in the other window:

```bat
cd /d D:\git\secret-keeper
scripts\start-copilot.cmd
```

The installer creates src/secret_keeper/request_capture.py.before-patch-12.
It is idempotent. If it rejects your layout, send request_capture.py; do not
manually bypass the safety checks.

## Behavior

Option sk_allow_verified_assistant_credentials defaults to true.
Disable with --set sk_allow_verified_assistant_credentials=false on your proxy
command. The install command is required; extraction alone does not enable it.

The helper observes successful HTTP responses without changing forwarded chunks.
It reconstructs complete assistant text from recognized JSON or SSE formats:
- OpenAI-style single-choice chat completions
- Responses API completed message/output_text objects and events
- Anthropic-style message/text_delta/message_stop formats

At stream end it stores answer hashes (not answer plaintext), request user-message
anchor hashes and a hashed host/Authorization scope. Cache: 256 answers, 30-minute
lookup lifetime. Observation buffer: at most 2 MiB PER active response. No disk
capture or external inspection is used.

A later messages[] or input[] assistant entry is eligible only if:
- its full text exactly matches a recorded completed upstream answer;
- destination host and Authorization header scope match;
- preceding user-message hashes preserve the original user-history prefix.
This is transcript-content scoping, NOT a verified provider conversation ID.
Token rotation, history truncation, formatting changes or unsupported content
can prevent matching. Role labels alone never grant an exemption.

Only credential_assignment inspection omits the eligible assistant content.
All other rules inspect the ORIGINAL payload, including that assistant text.
New user/tool/system content still receives credential checks. The request sent
upstream is never modified. A removed match produces:

Secret Keeper PROVENANCE EXEMPTION: verified model output excluded from
credential-assignment checks; other rules remain enforced

## Important limits

This is an initial HTTP provenance implementation, NOT a universal Copilot protocol
adapter. WebSocket-native responses are not recorded. Subsequent WS payloads can
benefit only if they use supported messages/input shapes and match an answer
recorded through HTTP. Opaque session-event envelopes remain strict.
Encoded/compressed responses, absent Authorization, unknown formats, partial/error
responses and oversize responses are NOT exempted. They keep existing enforcement.
No guessed protocol frames or artificial successful answers are injected.
This does not fix Copilot's pending-turn/retry behavior following real blocks.

Previously observed output is evidence of origin, not evidence that data is harmless.
This policy deliberately allows generic credential candidates in that output while
retaining other blocking rules. A user previously allowed under audit/disabled
credential policies could have supplied content later repeated by the model.
The helper does not track input-secret taint. Use the feature-disabled option if
that tradeoff is unacceptable. Restart clears provenance; cache state is not shared.
Changing an assistant history item or copying it into a user/tool field restores
normal credential inspection.

## Test procedure

Use a new disposable session with no file/tool reads:
1. Ask: Explain generally how passwords work. Do not read files or use tools.
2. Let the answer complete.
3. Ask: Explain salting without using tools.
4. If the prior answer contains a password-label example and Copilot resends it
   in a supported assistant-history shape, check for PROVENANCE EXEMPTION.
5. Separately send a new synthetic user disclosure; it must still block.

If it still blocks, that does NOT mean the verified-history exception failed:
it can mean response format/encoding or request shape was unsupported, content
changed, another rule matched, or provenance was unavailable. Do not weaken the
policy to force success. Obtain sanitized structural response/request diagnostics.

## Verification

102 unit tests passed under Python 3.12: 32 new provenance/integration cases plus
70 supplied request/rule cases. Tests cover JSON/SSE assembly, byte-preserving
stream forwarding, scopes, anchors, exact text, expiry, overflow, incomplete/error
responses, unchanged outbound payloads, other-rule enforcement, new-user/tool
blocks and feature disablement. Addon mitmproxy APIs are mocked.
Installer validated against the uploaded base addon layout; prior patches' preserved
fragments are used, but current patched checkout was not attached to rerun in full.
No live Windows 3.14 / mitmproxy 12.2.3 / Copilot test was performed.

## Rollback

Stop proxy. Restore the addon backup:

```bat
copy /y src\secret_keeper\request_capture.py.before-patch-12 src\secret_keeper\request_capture.py
```

Then restart the proxy. The helper can remain unused; no policy files changed.
