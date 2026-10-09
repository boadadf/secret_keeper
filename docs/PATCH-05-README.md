# Patch 05 — configurable rule blocker

Merge into repository root, preserving paths. Keeps request_capture.py and the CMD
launcher; no new dependency, certificate, or port changes. This patch replaces the
addon and its unit tests, adds a schema-2 public example, and does NOT overwrite
private config/secret-keeper-policy.json or any policy outside the checkout.

Stop proxy before merging. Run:
  .venv\Scripts\python.exe -m pytest -q tests\unit\test_request_capture.py
Run your existing local integration suite as a schema-1 compatibility check:
  scripts\test-proxy-integration.cmd
Optional schema-2 network extension:
  .venv\Scripts\python.exe tests\integration\run_rule_modes.py
Restart using your existing CMD launcher.

Existing schema-1 policies are accepted and converted in memory. Original IDs
(test_canary, dictionary, credential_assignment, etc.) remain for legacy audits,
so the original integration harness need not change. Source file is not migrated.
For schema 2, copy the example into your PRIVATE policy only after reviewing it.
Back up your real policy first; do not overwrite a customer dictionary with examples.
Public example contains only a fictional customer, disabled canary, secrets enabled.

Schema 2: rules list, each with opaque unique id, enabled boolean, type and action.
Types: exact_text (nonempty value, case-sensitive substring); dictionary (explicit
matching settings and entries); builtin (supported detector). No custom regex.
Actions: block or audit. Any block wins, independent of order. Every matched rule is
recorded once per payload (first matching location/entry only). AUDIT permits content
unless another rule blocks; final_decision makes conflicts explicit. Disabled rules
are skipped entirely. Empty rules is a valid allow-all CONTENT policy and must only
be used intentionally. Inspection/policy errors still reject. No all-secrets guarantee.

Builtins independently selectable: credential_assignment, credential_field,
private_key_block, supported_token_format. To turn off a category consistently,
consider BOTH credential_assignment and credential_field as applicable.

Dictionary matching: case_sensitive true/false, unicode_normalization NFKC/none,
whitespace collapse/preserve, boundary whole_phrase/substring. Whole phrase uses
Unicode word boundaries; substring may increase false positives. IDs must be unique
within rules (entries unique within their rule) and safe lowercase [a-z0-9_-], <=64
chars. Names should be registered as explicit aliases; values >=3 normalized chars.

Example action test: set synthetic-canary enabled=true, action=audit; restart proxy.
Fresh canary prompt should forward and produce AUDIT final_decision=ALLOW. Set action
block, restart, fresh session; expect HTTP 422 or WS drop. Disable the rule and restart;
expect forwarding without that match record. Never do audit-only tests with real data.

Policy changes require restart; unknown keys/settings and duplicate IDs rejected.
Metadata logs contain rule_id, detector, entry_id, location, action and final_decision,
not values/headers/URLs/bodies. Logging uses standard Python logging now; audit matches
are visible at error verbosity. Audit write failures do not undo blocking.

HTTP 422 and outgoing WS drop retained. Copilot rejection/retry UX unchanged.
Coverage remains bodies/UTF-8 message text, not headers/query/Base64/cross-message or
semantic identities. Credential-field/protocol false positives still possible. No
upstream credential validation, bounded custom regex, hot reload or admin UI added.
Unhandled addon/load failures and resource limits remain hardening work.

Delivery verification: supplied unit suite executed successfully in a synthetic
mitmproxy context. Live Windows/Copilot and updated network tests are pending. Previous
user verified 12 local rule/transport cases on Patch 04; do not transfer that result
unconditionally to this new implementation. Network extension reuses the original
integration helper file and skips nothing: missing original helper is a failure.

Publish code/tests/example only; private policies remain ignored. Preserve your
existing README, CHANGELOG, project record and launcher; append the supplied release
notes rather than overwriting other project documentation.
