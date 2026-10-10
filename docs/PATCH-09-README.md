# Patch 09: Live readable proxy console

Overlay this patch on the existing repository root, preserving paths.
This is a patch archive, not a complete standalone application.
Back up or commit your existing files first. No policies are included or overwritten.

## Git Bash (Windows)

```bash
SECRET_KEEPER_CONSOLE_CAPTURE=true SECRET_KEEPER_CAPTURE_MODE=off bash scripts/capture-requests.sh
```

## Windows CMD

```bat
set SECRET_KEEPER_CONSOLE_CAPTURE=true
set SECRET_KEEPER_CAPTURE_MODE=off
scripts\capture-requests.cmd
```

To use live console output together with existing sensitive file capture,
change SECRET_KEEPER_CAPTURE_MODE to full.
Disable console output with SECRET_KEEPER_CONSOLE_CAPTURE=false or unset it.
The launcher uses mitmdump and keeps termlog_verbosity=warn.
Console payloads are written and flushed directly to stdout, not diagnostic logging.

## Direct mitmdump use

Add `--set sk_console_capture=true` to your existing mitmdump command.
Default: false. Works with capture_mode=off and capture_readable=false.
The existing capture_max_payload_bytes limit also bounds console payload input.

## Display and safety

HTTP requests and outgoing client WebSocket messages use the existing readable
formatter. Includes time, flow ID, transport, rule IDs and ALLOW/BLOCK status;
console records also include destination host and port (not URL query strings).
ALLOW means the local policy allowed the attempted request, not confirmed delivery.

Console redaction is intentionally conservative: any rule match (block OR audit),
or unavailable decoded inspection text, withholds the ENTIRE body. Metadata and
rule IDs remain visible. The rule engine returns match metadata, not replacement
spans, so selective substring redaction cannot be guaranteed using its current API.
Unmatched payloads are visible and may still contain undetected secrets. Keep the
terminal private; output redirection and terminal history can retain this data.
Raw binary content is never dumped by the console feature.
Control characters are escaped using the existing formatter.

File capture behavior is unchanged: full capture can save unredacted sensitive
payloads, including blocked requests. Console redaction does not sanitize those files.
Console-only mode does not save payload files, but normal metadata audit logging remains.
Response bodies and server-to-client WebSocket messages are not displayed.
A slow terminal can slow request processing; limits constrain individual payloads,
not total console history. Console output failures do not change enforcement.

## Files

- src/secret_keeper/payload_capture.py
- src/secret_keeper/request_capture.py
- src/secret_keeper/readable_capture.py
- scripts/capture-requests.cmd
- scripts/capture-requests.sh (unchanged Windows wrapper)
- tests/unit/test_console_capture.py
- docs/PATCH-09-README.md
- docs/PATCH-09-TEST-RESULTS.txt

The private policy attachment and captured request attachment are not included.

## Verification

116 tests passed, 3 deselected using Python 3.12 in the build environment.
Includes existing request/capture/formatting tests and 14 new console cases.
Three existing tests could not be evaluated because scripts/read-capture.py and
scripts/start-copilot.cmd were not supplied: test_viewer_filter,
test_viewer_bad_record, test_quickstart_files.
Windows launcher and live mitmdump/network integration were not executed here.
Run the complete suite in your checkout:

```bat
.venv\Scripts\python.exe -m pytest tests/unit -q
```
