# Patch 10: Block feedback and WebSocket termination

This patch requires the existing project and Patch 09. Extract at repository root.
It replaces only request_capture.py and adds tests/documentation. Patch 09's
payload_capture.py, readable_capture.py and launchers remain untouched.
No policy, credentials, captures, or private configuration are included.
Back up/commit before applying.

## Changes

- Blocked HTTP requests still receive 422, now with a clear Secret Keeper error,
  blocking rule IDs, retryable=false and X-Secret-Keeper-Blocked: true.
- Blocked outgoing WebSocket messages are dropped BEFORE requesting flow.kill().
- A clear SECRET KEEPER REJECTED console notice provides rule IDs and recovery
  instructions without printing the offending content.
- Audit-only matches never terminate the WebSocket.
- Termination failure/unavailable state leaves the message dropped and logs a warning.
- Patch 09 console option/configuration updates remain supported.

## Important limitations

flow.kill() is a mitmproxy flow termination API, not a provider-specific error
message. This requests connection termination, not a graceful WebSocket policy
close frame with code 1008. No invented Copilot protocol frames are injected.
Copilot may show a generic transport error, retry, or continue waiting depending
on its behavior. This patch cannot guarantee an in-Copilot explanatory message
or a bounded client wait time. Actual socket termination and Copilot UI response
must be tested on Windows with the installed mitmproxy version.
retryable=false is advisory JSON; the client may not honor it.
The proxy notice is authoritative about the local block.
Terminating a WebSocket can affect other work multiplexed on the same connection.
Already forwarded content is not recalled. Full payload capture, if enabled,
retains its existing sensitive/unredacted behavior.

## Restart using Windows CMD

Stop the proxy using Ctrl+C in its own window, then:

```bat
cd /d D:\git\secret-keeper
set "SECRET_KEEPER_CONSOLE_CAPTURE=true"
set "SECRET_KEEPER_CAPTURE_MODE=off"
scripts\capture-requests.cmd
```

In the other CMD window, exit the old Copilot process and relaunch:

```bat
cd /d D:\git\secret-keeper
scripts\start-copilot.cmd
```

Use a fresh session if old history contains protected content.

## Manual checks

1. Send: Reply with exactly: SECRET_KEEPER_CONNECTION_TEST
   Expected: normal answer; no policy block.
2. In a disposable session, send: password="synthetic-test-secret"
   Expected with credential-assignment blocking enabled: HTTP 422 / WebSocket
   dropped and flow termination requested; proxy prints SECRET KEEPER REJECTED.
3. Observe whether Copilot exits the pending turn or reports a transport failure.
   If it remains pending, cancel the turn; record client behavior and proxy output.
4. In a fresh session, repeat the harmless connection test to confirm recovery.
5. Check audit-only matches remain allowed and do not terminate their flow.

## Tests

79 tests passed under Python 3.12: 70 supplied request/rule unit cases plus 9 new
block-feedback cases. mitmproxy APIs were mocked (mitmproxy is not installed in
this build environment). This does NOT constitute live network integration or
Windows/Copilot verification.
Run in your repository:

```bat
.venv\Scripts\python.exe -m pytest tests\unit -q
```
