# Secret Keeper: engineering and presentation record

Date: 2026-10-09. This record summarizes the development conversation and user-reported
Windows tests. It is not a certification, proof of universal coverage or release claim.
Do not append real payloads, credentials, personal identifiers or session IDs.

## Goal
A company-controlled inspection boundary for AI developer tools: lightweight proxy,
local deterministic rules, optional company-hosted GPU semantic validator.

## Decisions
- Explicit HTTPS inspection with a client-trusted local CA.
- Python orchestration with mitmproxy as initial engine, not custom TLS code.
- Working project name changed from Egress Guard to Secret Keeper (secret_keeper).
- Two planned repositories: secret-keeper and secret-keeper-validator.
- AI service gives findings; proxy holds requests and enforces decisions.
- Windows end-user target: self-contained application/installer, not Python setup.
- Policy files are trusted admin configuration; request content cannot weaken them.

## Progress and findings
1. Created initial source structure, validated configuration, CLI, engine adapter,
   unit tests, Windows/Linux CI definition, security docs and release roadmap.
2. Windows execution policy blocked unsigned PowerShell scripts. Developer testing
   used Git Bash for proxy and CMD for Copilot. Product packaging is pending.
3. Corrected source engine discovery dependent on PATH, and incomplete rename in
   test imports and console entry-point metadata. User reported 11 unit tests passing.
4. HTTPS curl smoke test succeeded with the local CA. Windows Schannel needed
   best-effort revocation for the synthetic test; certificate verification remained on.
5. Copilot sign-in and a harmless prompt worked through the proxy.
6. With proxy stopped, sign-in and new requests in an existing session failed.
   This confirms dependency for tested operations, not every possible operation.
7. Initial capture showed unavailable POST bodies incorrectly counted as zero bytes.
   Cause: stream_large_bodies=0 sets a zero-byte threshold, not disabled streaming.
8. Request-buffering patch recovered HTTP bodies; responses explicitly stream.
9. User-supplied synthetic capture showed prompt-bearing routing requests, an auxiliary
   classification call and a large session-event payload containing context/instructions.
10. Session events reported a WebSocket model transport. That was indirect metadata,
    not the actual outgoing WebSocket model message captured by our addon.
11. Patch 02 adds direct outbound WebSocket capture and transport-labelled records.
    Live Copilot verification is pending. Eight synthetic addon tests passed when
    generating this archive; substitutes do not exercise actual engine networking.

## Current capability and limits
Diagnostic HTTP and outbound WebSocket capture; no validation enforcement yet.
No local LLM, internal AI server, mandatory network routing, production installer,
log rotation or demonstrated all-transport policy boundary. Payload logs are sensitive.
Long-lived WebSocket memory retention, request limits and capture permissions need work.

## Next milestones
- Verify live outbound WebSocket payload capture with synthetic markers.
- Integration tests against a controlled upstream, including streaming and TLS failures.
- Block a deterministic canary before upstream transmission on HTTP and WebSocket.
- Implement versioned authenticated validator contract and policy engine.
- Bound concurrency, payload sizes, disk usage and engine memory retention.
- Add retention, ACL handling, certificate lifecycle and safe audit metadata.
- Clean Windows packaging tests, dependency locks, license audit, SBOM and signing.
- Evaluate contextual-policy accuracy and false positives before making detection claims.

## Future LinkedIn narrative (outline, not published)
Problem: outgoing AI-agent traffic includes more than the visible user prompt.
Approach: open-source company-controlled inspection before transmission.
Demonstration: actual Windows Copilot compatibility and multiple observed request paths.
Architecture: lightweight client; local rules; optional internal GPU validator.
Credibility: publish tested scope, threat model and limitations. Do not claim guaranteed
zero leakage, production readiness, novel category, or an existing public repository.
Do not publish raw captures, customer data, internal identifiers or system-prompt dumps.
Add a GitHub URL only after repository publication and review.

## Local verification notes
Record date, engine/client versions, synthetic test name and pass/fail only.
Patch 02 live verification: PENDING.
