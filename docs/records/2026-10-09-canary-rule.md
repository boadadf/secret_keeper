# 2026-10-09 — Canary rule increment

User verified actual outbound WebSocket capture: one client-to-server /responses
message, 96,727 bytes, containing the synthetic test marker. No payload copied here.

Patch 03 adds fixed synthetic canary blocking in the existing addon. Local HTTP 403;
outgoing WebSocket message drop. Blocked bodies are not persisted, enforcement is
independent of diagnostic capture. Nine synthetic unit tests passed during archive
creation. Live Copilot blocking and controlled upstream non-receipt remain pending.
This is not a completed DLP system or universal no-leak guarantee. Keep LinkedIn
claims aligned to tested transport and enforcement scope.
