# Real-proxy local integration checks

Merge the two files into repository root, preserving paths. No addon changes,
no extra Python packages, no GitHub connection. Uses existing venv mitmdump.

Run in CMD from repository root:
  scripts\test-proxy-integration.cmd

Starts separate local HTTP/WebSocket server and real mitmdump on temporary ports.
Uses isolated temporary policy, audit and certificate state. Does not edit your
working policy, use port 8080, modify your trusted CA, or require Copilot.
All payloads synthetic. Temporary state/logs are deleted on normal completion;
forced interruption can leave temporary files and processes.

Tests three rules over HTTP and WebSocket with audit on and off: 12 combinations.
Each has positive allow controls. WS blocked content is followed by allowed content;
server echoes received messages, so receiving the later echo establishes progress.
HTTP rejects must return 422 with secret_keeper_blocked and not reach upstream.
Audit-enabled runs additionally require matching BLOCK records per transport/rule.
Timeouts/connection failures are FAIL, never treated as success.

Expected final output:
PASS: 12 transport/rule checks across audit-enabled and audit-disabled runs.

Initial delivery validation: Python syntax checked and frame helper roundtrips
checked. Full Windows/mitmdump execution has NOT been performed by the assistant.
Please report PASS/FAIL and diagnostic output. Do not mark integration verified yet.

Coverage: local HTTP and WS UTF-8 text; no HTTPS/WSS, fragmentation, binary messages,
resource/size stress, all inspection errors, history or client UX. This is a focused
first integration harness, not full release certification. Port-selection race is
possible and fails the run. Retry if another process claimed the selected port.
