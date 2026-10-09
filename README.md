# Secret Keeper

Stop configured sensitive information from being sent to an external AI service.

Secret Keeper runs between your AI tool and its server. It checks outgoing content against rules you control. If a blocking rule matches, it stops the request or message.

You can block customer names, internal addresses, passwords, keys, and other information that must not leave your environment.

**Important:** Only traffic passing through Secret Keeper is checked. It does not automatically protect every application or detect every possible secret.

## How it works

```text
Your AI tool
    |
    v
Secret Keeper checks the outgoing content
    |
    +-- Blocking rule matches --> Stop the request
    |
    +-- No blocking rule ------> Send it to the AI service
```

The current rules run locally without an LLM. Secret Keeper does not send suspected credentials to a provider to check whether they work.

It inspects HTTP request bodies and outgoing WebSocket messages. These are two ways AI clients send information to their servers.

## Current version

Patch 07 adds optional payload capture to the rule blocker from Patch 06.

- The maintainer reports working live rule tests and working payload capture.
- The earlier local HTTP/WebSocket test suite passed 12 checks.
- Patch 06's 70 synthetic unit tests passed during package generation.
- Patch 07's 17 capture-helper tests passed during package generation.
- Run the combined tests and updated network suites on your installed version before declaring that release verified.

Copilot's error presentation and retry delay remain unfinished. A test result applies to the tested scenarios, not every application, protocol, or secret.

## What you can block

| Information | Rule or detector |
|---|---|
| Company/customer names and aliases | Dictionary |
| Fixed confidential markers | Exact text |
| Internal URLs | Configured domains/subdomains |
| Email addresses | Registered addresses or domains |
| IPv4/IPv6 addresses | Configured network ranges |
| Usernames and employee IDs | Registered structured fields and values |
| Paths, bucket names, repository names | Registered resource strings |
| Password/key/token assignments | Credential-assignment detector |
| JSON credential fields | Credential-field detector |
| Private-key blocks | Supported paired key markers |
| Some provider token shapes | Supported-token detector |
| Credential-bearing connection strings | Connection-string detector |
| Encoded text | Bounded percent, hex, and Base64 decoding |
| Card and IBAN candidates | Format/checksum detectors |
| Phone, hash, random-looking strings | Optional candidate detectors |

A pattern match does not prove a real secret exists. A public checksum, example credential, or protocol field can match. Phone detection is shape-only, not country-aware verification. Provider-token coverage is limited.

The example policy puts card, IBAN, phone, hash, and entropy candidates in audit mode rather than blocking them.

## Rule actions

| Configuration | Behavior |
|---|---|
| Enabled + `block` | Stop matching content |
| Enabled + `audit` | Record the match and allow it unless another rule blocks |
| Disabled | Do not evaluate that rule |

Any block wins, regardless of rule order. Audit mode does not prevent disclosure.

## Windows setup

Use Windows Command Prompt (CMD) for the documented workflow.

From the repository root, install the declared development dependencies:

```bat
py -3.12 -m venv .venv
.venv\Scripts\python.exe -m pip install -e ".[dev]"
```

This assumes the repository's `pyproject.toml` defines the `dev` extra. The supplied development setup script also uses Python 3.12.

Your client must be configured to use the proxy. For HTTPS interception, it must trust the proxy certificate. Starting the proxy does not configure the client automatically. Keep your existing working certificate setup; do not disable upstream TLS verification as a workaround.

### Create a private policy

Keep real company rules outside the checkout. The CMD launcher defaults to:

```text
%LOCALAPPDATA%\SecretKeeper\secret-keeper-policy.json
```

For a new policy only:

```bat
if not exist "%LOCALAPPDATA%\SecretKeeper" mkdir "%LOCALAPPDATA%\SecretKeeper"
if not exist "%LOCALAPPDATA%\SecretKeeper\secret-keeper-policy.json" copy config\secret-keeper-policy.example.json "%LOCALAPPDATA%\SecretKeeper\secret-keeper-policy.json"
notepad "%LOCALAPPDATA%\SecretKeeper\secret-keeper-policy.json"
```

Review the fictional example before using it. Replace its sample values only in your private policy. Back up existing policies before changing them.

### Start the proxy

```bat
scripts\capture-requests.cmd
```

The historical launcher name is unchanged. It starts the content-policy proxy, not full payload capture by default.

The launcher uses:

- `127.0.0.1:8080` as the listening address.
- `%LOCALAPPDATA%\SecretKeeper` for certificate state.
- A private policy outside the repository.
- A metadata-only audit file under `%LOCALAPPDATA%\SecretKeeper\logs`.

Keep it running in one CMD window and use another for your AI client. Stop it with `Ctrl+C`.

For a different private policy:

```bat
set "SECRET_KEEPER_POLICY=C:\CompanyPolicy\secret-keeper-policy.json"
scripts\capture-requests.cmd
```

The file must exist. Restart the proxy after policy edits.

## Optional full payload capture — Patch 07

Capture is off by default. Enable it only when you deliberately want to save outgoing content for later local analysis.

It can save confidential information, including blocked attempts and old conversation context. Store captures outside Git, restrict access, and remove them after analysis.

### Enable capture

Stop the proxy. Add these options to the existing `mitmdump` command in your CMD launcher:

```bat
--set capture_mode=full --set "capture_file=%LOCALAPPDATA%\SecretKeeper\captures\outbound.jsonl"
```

For a multiline launcher, its final section can be:

```bat
  --set "request_log=%LOG%" ^
  --set "secret_keeper_policy=%SECRET_KEEPER_POLICY%" ^
  --set capture_mode=full ^
  --set "capture_file=%LOCALAPPDATA%\SecretKeeper\captures\outbound.jsonl"
```

These are proxy command options, NOT fields in the rule-policy JSON. Audit and capture must use different files.

Restart:

```bat
scripts\capture-requests.cmd
```

Look for:

```text
Secret Keeper FULL CAPTURE ACTIVE
```

`CAPTURE ERROR` means capture was disabled because the configuration was invalid or could not be used. `CAPTURE WRITE FAILED` means a record was not guaranteed saved. Neither intentionally disables rule enforcement.

### What is saved

- Attempted outgoing HTTP bodies and WebSocket payloads.
- Allowed and blocked content.
- Raw bytes stored as Base64.
- Available decoded text.
- Flow ID, time, transport, matched rule IDs, and final allow/block decision.

The record uses `capture_stage: attempted_outbound`. `ALLOW` means permitted to forward, not proof that the destination received it.

For HTTP, raw bytes may be compressed; available `body_text` is the text the addon inspected. Incoming messages, headers, full URLs, traffic bypassing the proxy, and files outside the payload are not captured.

### Limits and rotation

| Option | Default |
|---|---|
| `capture_mode` | `off` (`full` is the other supported value) |
| `capture_file` | No default; required for full capture |
| `capture_max_payload_bytes` | 1048576 — 1 MiB per raw/text representation |
| `capture_max_file_bytes` | 16777216 — 16 MiB rotation size |
| `capture_backups` | 3 rotated backups plus the current file |

Larger representations are truncated. Records flag this using `raw_truncated` and `text_truncated`. Rotation removes the oldest backup. This is a rolling debugging capture, not a complete indefinite archive.

There is no redacted capture mode, encryption-at-rest feature, automatic age expiry, or secure-erasure feature. Windows folder permissions need administrator review. Use one writer per capture file. Capture adds disk work and can increase latency.

### View and disable capture

```bat
notepad "%LOCALAPPDATA%\SecretKeeper\captures\outbound.jsonl"
```

To disable it, remove the capture options or set:

```bat
--set capture_mode=off
```

Restart the proxy. Disabling capture does not delete old files. Do not publish captures or upload them automatically to an external AI service.

## Configure blocking rules

Schema version 2 uses a `rules` list:

```json
{
  "schema_version": 2,
  "rules": []
}
```

An empty list allows inspectable content. Use it only intentionally. Version-1 policies remain supported and are converted internally without rewriting the source file.

### Customer-name dictionary

```json
{
  "schema_version": 2,
  "rules": [
    {
      "id": "customer-names",
      "type": "dictionary",
      "enabled": true,
      "action": "block",
      "matching": {
        "case_sensitive": false,
        "unicode_normalization": "NFKC",
        "whitespace": "collapse",
        "boundary": "whole_phrase"
      },
      "entries": [
        {
          "id": "customer-001",
          "values": ["Northstar Manufacturing", "Northstar Manufacturing GmbH"]
        }
      ]
    }
  ]
}
```

This matches different letter case and normalized whitespace. `Northstar` alone does not match the full registered phrase. Register aliases explicitly. `substring` instead of `whole_phrase` matches inside larger strings but can produce more unwanted matches.

### Internal URLs

Add this rule to your list:

```json
{
  "id": "internal-urls",
  "type": "url_domain",
  "enabled": true,
  "action": "block",
  "domains": ["example.internal"],
  "include_subdomains": true
}
```

It checks URLs inside content, not which servers an application may contact.

### Usernames in structured fields

```json
{
  "id": "registered-usernames",
  "type": "field",
  "enabled": true,
  "action": "block",
  "fields": ["username", "login", "employee_id"],
  "values": ["synthetic-user-001"],
  "case_sensitive": false
}
```

This matches registered structured fields. Use a dictionary to match a username in ordinary prose. An empty `values` list means any nonempty, non-redacted scalar in those fields can match.

### Built-in detectors

```json
{
  "id": "credential-assignments",
  "type": "builtin",
  "enabled": true,
  "action": "block",
  "detector": "credential_assignment"
}
```

Available names:

| Detector | Checks |
|---|---|
| `credential_assignment` | Password/key/token assignments |
| `credential_field` | Supported JSON credential fields |
| `private_key_block` | Paired private-key markers |
| `supported_token_format` | Implemented token/identifier shapes |
| `connection_string` | Credentials and selected signature parameters in text forms |
| `credit_card` | Candidate format and Luhn checksum |
| `iban` | Generic candidate format and mod-97 checksum |
| `phone_candidate` | International `+`-prefixed number shapes |
| `hash_candidate` | Common hexadecimal hash lengths |
| `entropy_candidate` | Long, random-looking token shapes |

Detectors can overlap. Disabling one does not stop another matching the same content.

Rule IDs are logged. Use opaque IDs rather than sensitive names. IDs must be unique and contain only lowercase letters, digits, hyphens, or underscores, up to 64 characters. Invalid settings or duplicate IDs cause a policy error.

See the public example and patch documentation for email, network, resource, and inspection settings.

## Decoding and inspection limits

The example enables percent, hex, and Base64 decoding up to two layers. Existing policies without the optional `inspection` settings default to decoding disabled.

Supported decoded text is checked against the same rules. This does not decode every file or encoding: no images, compressed archives, arbitrary binary formats, or cross-message reconstruction.

The default inspected-text limit is 2 MiB. The launcher's 10 MiB transport-body limit is separate. Exceeding inspection work/size limits produces `inspection_limit`.

Capture limits and inspection limits are separate: saving a truncated capture does not deliberately reduce the content inspected by the blocker.

## Test the installation

Use synthetic credentials and fictional customers only.

### Automated tests

```bat
.venv\Scripts\python.exe -m pytest -q tests\unit\test_request_capture.py tests\unit\test_payload_capture.py
scripts\test-proxy-integration.cmd
.venv\Scripts\python.exe tests\integration\run_rule_modes.py
scripts\test-expanded-rules.cmd
```

For the supplied unchanged files:

| Suite | Expected |
|---|---|
| Rules and capture unit suites | 70 + 17 tests |
| Original local HTTP/WebSocket suite | 12 checks |
| Rule-mode suite | 16 checks |
| Expanded detector suite | 64 checks |

The network suites start local servers and isolated proxies. They verify that allowed content arrives and rejected content does not. Timeouts are failures, not proof of blocking. The existing suites do not by themselves verify full-capture mode over the network, HTTPS/WSS certificate behavior, or Copilot retries.

### Live checks

In a fresh AI-client conversation, first send:

```text
Reply with hello.
```

It should pass. Then test an enabled credential rule:

```text
password = "Synthetic-Only-42"
```

It should block. With capture enabled, the normal attempt should have an `ALLOW` capture and the rejected attempt a `BLOCK` capture.

### Canary test

Add or enable:

```json
{
  "id": "synthetic-canary",
  "type": "exact_text",
  "enabled": true,
  "action": "block",
  "value": "SECRET_KEEPER_CONFIDENTIAL_CANARY"
}
```

Restart, start a fresh conversation, then send:

```text
Reply with exactly: SECRET_KEEPER_CONFIDENTIAL_CANARY
```

Expect a canary block. Disable the rule afterward unless you want the marker blocked. Exact text means the literal sequence can appear anywhere in inspected content, not that the whole message must equal it.

## Why a harmless prompt can block

Secret Keeper checks the whole outgoing payload, including history/context when included by the client.

```text
Previous context: SECRET_KEEPER_CONFIDENTIAL_CANARY
Newest prompt:    Reply with hello.
```

If both are sent together, an enabled canary rule correctly blocks. The same applies to secrets in included attachments or tool output. Use a new conversation after a blocking test; do not resume a contaminated session.

## Rejections and logs

HTTP blocks return local status 422 with `secret_keeper_blocked`. Outgoing WebSocket blocks drop the message. Your client may show an error, wait, or retry. Secret Keeper does not silently redact or rewrite prompts.

The audit log remains metadata-only even when full capture is enabled. It contains decisions, time, transport, flow ID, rule/detector IDs, safe structural location, and final decision. It does not contain payload text.

| Reason | Meaning |
|---|---|
| Configured rule ID | Content matched a rule |
| `policy_error` | Policy invalid or unavailable |
| `inspection_error` | Content could not be inspected |
| `inspection_limit` | Inspection size/work limit exceeded |
| `body_unavailable` | Buffered HTTP body unavailable |

`body.text` describes an inspected representation, not necessarily the newest visible prompt.

Old diagnostic logs are not erased by upgrades. Protect them as sensitive data. The metadata audit log has no automatic rotation; rotation options apply only to the new capture file.

## Current limitations

Secret Keeper does not currently:

- Inspect traffic bypassing the proxy or incoming WebSocket messages.
- Inspect actual request headers or URL/query components.
- Recognize every password, token, encoding, or indirect identity disclosure.
- Reconstruct secrets split across messages.
- Inspect images or arbitrary binary files.
- Use an LLM to assess confidential meaning.
- Provide complete administrator/resource hardening or fail-closed guarantees for unexpected addon/load failures.

Keep it as one layer of protection, not your only confidentiality control.

## Publishing and contributing safely

Publish code, tests, documentation, and safe example policies. Keep private rules, captures, logs, environment files, and certificate state out of Git.

The public policy example is `config/secret-keeper-policy.example.json`. A local `config/secret-keeper-policy.json` should be ignored; deployed policies should preferably live outside the checkout.

Review staged changes and history. Ignore rules do not remove previously committed content.

Contributions should include clear detector limits, allow/block tests, and synthetic false-positive examples. Never include real secrets or raw production traffic in issues or pull requests. Share safe metadata for diagnosis, not captured bodies.

## Next steps

- Optional local/on-premises LLM classification for confidential meaning.
- Better client rejection and retry behavior.
- Wider detector and edge-case testing.
- Stronger deployment, resource, and data-retention controls.

These are plans, not current features.

## License

See `LICENSE` for terms and `NOTICE` for attribution.
