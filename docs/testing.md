# Verification and acceptance

Automated unit tests cover configuration defaults/rejection and safe engine arguments.
CI is provided for Windows and Linux; generating this archive does not run GitHub CI.

Before a release, run synthetic end-to-end tests against a locally controlled HTTPS
origin and a test CA (do not commit keys). Assert:

- GET, POST, JSON, binary and multipart payload preservation;
- upstream certificate rejection when invalid;
- request cancellation and upstream failures;
- streaming response arrival before completion, including SSE;
- compression, HTTP/1.1 and HTTP/2 behavior;
- quiet output excludes sentinel body, Authorization and sensitive URL values;
- clean shutdown releases the port; malformed config exits nonzero;
- Copilot CLI and VS Code work on recorded versions;
- no internet content is captured persistently by default;
- fresh-user Windows installation, trust removal and uninstall work;
- memory/body limits and concurrency budgets are established before production.

No live Copilot/VS Code tests or Windows executable tests were performed while
creating this archive. Unit tests are not evidence of client interoperability.
