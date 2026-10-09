# Patch 06 — expanded deterministic content rules

Merge into repository root, preserving paths. Replaces the addon and its unit-test
file. Adds adjacent rules.py (REQUIRED), integration suite, CMD test launcher and
public example policy. No new runtime dependency, no launcher/policy/CA overwrite.
The addon imports rules.py by absolute adjacent file path; launch command unchanged.

Stop proxy; back up current code/private policy. Extract ZIP to repository ROOT,
not src. Run in CMD:
  .venv\Scripts\python.exe -m pytest -q tests\unit\test_request_capture.py
  scripts\test-proxy-integration.cmd
  .venv\Scripts\python.exe tests\integration\run_rule_modes.py
  scripts\test-expanded-rules.cmd
The last two commands need earlier integration files already in your repo. Tests
use isolated ports/policies/temp CA state, not real credentials or Copilot. Expanded
network suite has 16 cases x 2 transports x logging on/off = 64 checks; each case
starts an isolated proxy, so it is slower than a unit suite. No timeout counts as PASS.

Existing schema-1 and old schema-2 policies load without modification. New rules
are NOT automatically inserted in private policies. Builtin supported_token_format
now has additional pattern shapes; inspection limits also apply to legacy policies.
The default input limit is 2 MiB, not the launcher 10 MiB: larger inspected text
returns inspection_limit. Change max_input_bytes deliberately if larger needed.

To activate new rules: review config/secret-keeper-policy.example.json, back up your
private policy, and merge selected rules/settings into it. Do NOT overwrite actual
customer policy with examples. Example has fictional domains/users/paths; replace
only locally. No private configuration shipped or read during patch generation.
Restart after every policy edit. Example canary disabled; generic hash/entropy,
phone, credit-card and IBAN detectors audit-only. Audit means data WILL forward
unless another block rule matches. Enable block for these only under explicit policy.

New rule types:
- url_domain: domains + include_subdomains. Parsed scheme:// URL host matching with
  IDNA/case/trailing-dot normalization and correct suffix boundary. Not bare-domain
  detection, destination allowlist, DNS lookup, or URL/query/header inspection.
- email: domains, include_subdomains, addresses. ASCII email recognition; addresses
  matched case-insensitively. Internationalized mailbox forms not comprehensively covered.
- ip_network: explicit canonical CIDR networks (strict=True), IPv4/IPv6. Supports
  IPs in body text/URLs, not resolving hostnames or blanket private-IP classifications.
- field: fields, values, case_sensitive. Structured JSON fields only; an empty values
  list blocks any nonempty/non-redacted scalar in registered fields. Nonempty values
  list is exact-match against that field's value. Fields normalized like credential
  fields; do not use dots for JSON paths. Plain username prose needs a dictionary.
- resource: values, case_sensitive. Literal substring rules for registered paths,
  bucket/repo names or hashes. Not filesystem access, glob matching or fingerprints.

New builtins:
- connection_string: credential-bearing scheme:// URIs, selected credential/signature
  query fields inside those URIs, and password/pwd assignments in semicolon-style
  strings. No protocol-specific exhaustive parser, real request-header inspection,
  credential validation, or network provider calls.
- credit_card: 13-19 digit candidate plus Luhn checksum, rejects uniform digits. Not
  issuer validation; test values or other identifiers can pass this checksum.
- iban: generic syntax/length plus mod-97 checksum. No country-specific registry or
  country-specific length validation; recognition can miss text boundary variants.
- phone_candidate: international +prefix-shaped numbers ONLY, no country-aware
  parsing or proof number exists. Audit first; not a complete phone recognizer.
- hash_candidate: isolated 32/40/64/128 hex strings. Does NOT establish sensitivity
  or detect content whose registered document hash was supplied.
- entropy_candidate: 32-256 character token-shaped strings with Shannon entropy >=4.5.
  A heuristic, not authenticity; audit first. Threshold not individually configurable.
- supported_token_format expanded: legacy GitHub, github_pat_ (82 chars), GitLab
  glpat- (20 chars), Stripe sk_live_ (24-128), Slack xox[baprs]- (20-200), AWS AKIA
  identifiers. Format candidates only, not exhaustive provider/token coverage.

Existing dictionary/exact_text/builtins and block/audit/disabled semantics retained.
Every block wins; at most one first location per matching rule, no matched text logged.
No custom regex, arbitrary user pattern execution, redaction or rule bypass added.

Optional inspection object (schema 2):
  max_input_bytes: 1024..10485760 (default 2097152)
  max_views: 16..10000 (default 4096)
  max_json_depth: 4..128 (default 64)
  decode_depth: 0..3 (default 0 for existing policies)
  max_decoded_bytes: 1024..2097152 (default 524288)
  decoders: unique list from percent, hex, base64 (default [])
Example enables all decoders at depth 2. Percent decode whole text with escapes;
hex/Base64 scan bounded candidate tokens 16-8192 chars. Strict UTF-8 decoded text
only; decoded JSON is parsed and strings/keys inspected. No gzip, images/OCR,
arbitrary binary, unbounded recursive decode, Base64 with whitespace reassembly,
full URL-encoded form parser or cross-message reconstruction. Decode budgets count
candidate bytes conservatively (including duplicates/non-UTF8 attempts) and exceedance
blocks with inspection_limit. Binary decoded values otherwise skipped. Limits reduce
risk but are not CPU deadlines or complete ReDoS/resource hardening.

70 unit delivery checks passed with synthetic fixtures; full Windows/network execution
pending. Re-run prior suites before claiming regression-free behavior. HTTP 422 and
WebSocket drop unchanged; Copilot retries/UX unresolved. HTTPS/WSS work deferred.
Optional local LLM semantic validation deliberately NOT included in this patch.
Do not claim universal no-leak protection; only routed inspected content is covered.

Publication: ship code, tests, safe example, records only. Keep private policies,
logs, state and old raw captures out of Git. Patch README is delivery guidance;
merge relevant content into main documentation before a public release.
