# Release roadmap

0.1: source foundation; explicit loopback pass-through proxy, configuration, unit tests.
Next: local-origin integration suite, safe metadata observability and health reporting;
body limits, graceful shutdown and streaming tests; dependency lockfiles and engine
version qualification; clean Windows packaging spike.
Then: policy interface, synthetic deterministic rules and local model integration.

Windows end-user goal: unzip-and-run bundle or signed per-user installer; no separate
Python, pip or mitmproxy installation. Installer trust changes must be explicit and
reversible. No silent certificate trust. Use Windows runners for native builds.

Release gate: exact dependency resolution, vulnerability and license review, SBOM,
checksums, code signing, build provenance, supported OS/client matrix, clean-machine
smoke tests and security review. CI dependency ranges in this delivery are not a
reproducible release lock. Signing credentials must remain outside source control.
