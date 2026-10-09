# Threat model — first delivery

Assets: user request content, authentication headers, CA private key, client trust.
Trust boundary: plaintext exists inside the local proxy process after TLS termination.
The engine and launcher run as the user. Do not run as administrator by default.

This is an explicit opt-in proxy, not an enforced network gateway. Applications may
bypass it. This release does not detect secrets, guarantee data-loss prevention,
provide proxy authentication, or support remote listeners. Unsupported protocols,
certificate pinning and client trust-store differences may prevent interception.

No flow files or payload logging are configured. Engine stderr may include endpoint
metadata. Memory, crash dumps and OS diagnostics can expose content. No secrecy
claim applies to a compromised host or privileged local attacker.

Large-body streaming is disabled in this foundation so future validation does not
accidentally inherit early-forwarding behavior. There is no hard body-size limit in
this release: buffering creates memory-exhaustion risk. This is a release blocker
for unattended production use. Uninstall/rotation, dependency locking, signed
binaries, log sanitization tests and protocol acceptance tests remain required.

Secrets rule: never read, print, copy, transmit or commit credentials, private keys,
production configuration or real customer data as development/test material. Use
synthetic fixtures and example configuration. If a secret is required, stop and
report the requirement without requesting or displaying its value.
