# Changelog

## 0.1.0 — first source delivery

- Loopback-only explicit inspecting proxy launcher.
- Validated versioned TOML configuration and public certificate locator.
- Quiet engine defaults and no policy/business logic.
- Windows/Linux source CI, unit tests and product/security documentation.
- Windows standalone installer explicitly deferred.

### Verified: local proxy integration tests

Passed 12 rule/transport combinations covering canary, dictionary,
and synthetic credential detection over HTTP and WebSocket, with
audit logging enabled and disabled.

Controlled upstream receipt checks confirmed that allowed payloads
arrived and rejected payloads did not arrive in these scenarios.
WebSocket checks also confirmed that an allowed message following
a blocked message was delivered.

Not covered: HTTPS/WSS, fragmented messages, arbitrary binary
payloads, resource-limit behavior, or Copilot rejection/retry UX.