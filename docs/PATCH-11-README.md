# Patch 11: Deterministic detection coverage

Overlay on your existing repository AFTER Patches 09 and 10.
Only src/secret_keeper/rules.py is replaced. The new tests and documents are added.
No launch scripts, proxy addon, payload formatter or policy files are replaced.
This preserves console capture and blocked WebSocket termination behavior.
Back up/commit existing files first.

## Actual changes

1. credential_assignment now additionally recognizes explicit English constructions:
   My password is synthetic-value
   Use this password to login: synthetic-value
   Use this password for authentication: synthetic-value
   Use synthetic-value as the password
   API key: synthetic-value
   client secret equals synthetic-value
   Labels cover password/passwd/pwd, API key/secret, client secret, access/refresh
   token, secret key and private key. Assignments, quoted values and multiline
   colon/equals forms are supported. Common non-value words in natural-language
   matches and existing redaction placeholders are excluded.
2. Configured field rules additionally recognize explicit label/value constructions
   in prose, respecting configured value lists and case sensitivity. This does not
   infer unconfigured field names or invent forbidden values.
3. JSON objects/arrays embedded inside JSON strings are now inspected structurally,
   within existing depth/view limits. This fixes credential_field coverage there.
4. IBAN extraction checks bounded candidates at separators rather than greedily
   swallowing trailing prose. Supports lowercase, spaces, tabs, line breaks,
   nonbreaking and narrow nonbreaking spaces. Existing length/checksum validation
   remains: it is not an authoritative country-format or account-existence check.
5. Card extraction accepts tabs and nonbreaking spaces alongside spaces/hyphens;
   Luhn validation remains. Alphanumeric boundaries avoid matching inside words.
6. Phone candidates accept common multi-character separator combinations such as
   +44 (20) 7946 0958. Still a candidate heuristic, not telephone-number validation.
7. Connection-string query fields include refresh_token, passwd, api-key,
   access-token, client-secret, secret_key and related variants.

Other categories retain their existing detection implementation, with regression
coverage added for exact text, dictionaries, private keys, supported tokens,
URLs/domains, email restrictions, IP networks, resources, hash/entropy candidates.
This is not a claim that every rule needed rewriting or that every possible format
is now covered.

## Policy behavior

No policy edits are necessary for natural-language credentials when the existing
credential_assignment rule is enabled. It obeys that rule's block/audit action.
Nothing is silently promoted from audit to block. IBAN/card/phone etc. only block
when YOUR ACTIVE policy enables them with action=block. Check the AppData policy,
not just the repository example:

```bat
notepad "%LOCALAPPDATA%\SecretKeeper\secret-keeper-policy.json"
```

The supplied example policy uses audit for several financial/PII candidate rules.
This patch does not modify it or your private policy.

## Windows CMD restart

Stop the proxy with Ctrl+C and restart in its own CMD window:

```bat
cd /d D:\git\secret-keeper
set "SECRET_KEEPER_CONSOLE_CAPTURE=true"
set "SECRET_KEEPER_CAPTURE_MODE=off"
scripts\capture-requests.cmd
```

Restart Copilot in the other CMD window:

```bat
cd /d D:\git\secret-keeper
scripts\start-copilot.cmd
```

Use a disposable fresh session for synthetic block tests; retained history containing
protected data can cause subsequent turns to block too.

## Manual tests

With credential_assignment enabled as block:
- Explain how passwords work -> no credential-assignment match
- Use this password to login: synthetic-test-secret -> credential-assignment match
- My API key is synthetic-test-value -> credential-assignment match

For IBAN (obeys active action):
- Transfer to GB82 WEST 1234 5698 7654 32 please -> IBAN match
- Explain how IBAN checksums work -> no IBAN match

Never test with actual credentials.

## Limits / security

This is deterministic pattern recognition, not semantic understanding. It supports
explicit English constructions, not all languages/paraphrases or adversarial obfuscation.
A benign quoted example containing a secret-looking disclosure can still match.
Non-value exclusions are heuristic and can miss a real password equal to an excluded
word in a natural-language construction (assignment syntax remains stricter).
Unlabeled arbitrary passwords are not distinguishable from ordinary text.
Checksum matches do not establish whether an account/card exists or belongs to someone.
Embedded-JSON depth/view limits can cause fail-closed inspection_limit blocks.
No LLM/network inspection dependencies were added.

## Verification

484 cases passed: 383 new deterministic regression cases plus 101 existing cases.
Tests cover all eight existing rule types and all eleven builtin detectors, with
plain text, JSON, nested JSON-string wrappers, block/audit/disabled policy variants,
positive/negative cases and formatting variations.
Four existing tests were deselected because repository dependencies were not staged:
test_viewer_filter, test_viewer_bad_record, test_quickstart_files,
test_setup_preserves_policy. They do not test this rule-engine modification.
No Windows/live mitmproxy/Copilot integration was executed; addon tests use mocks.
Patches 09/10's new tests were not available in this build workspace and were not rerun.

Run the full suite in your checkout:

```bat
.venv\Scripts\python.exe -m pytest tests\unit -q
```
