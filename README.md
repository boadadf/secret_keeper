# Secret Keeper

Keep control of the information your AI tools send to external servers.

Secret Keeper is a local proxy. It checks outgoing content against rules you choose and stops requests/messages that match a blocking rule. You can also save attempted outgoing content locally in a readable format for review.

**Important:** It checks only traffic routed through it. It is an experimental protection layer, not a guarantee against every leak.

## What it does

- Blocks registered company/customer names, internal URLs, email addresses, network addresses, identifiers, and resource names.
- Detects selected password assignments, JSON credential fields, private-key blocks, token shapes, and credential-bearing connection strings.
- Optionally checks supported encoded text, checksum candidates, phone shapes, hashes, and random-looking strings.
- Inspects HTTP request bodies and outgoing WebSocket messages.
- Keeps a metadata-only audit log by default.
- Optionally creates BOTH a machine-readable capture and a readable text companion.

Rules run locally without an LLM or online credential validation. An optional local semantic validator is planned, not implemented.

## Windows quick start: from clone to first test

These instructions use Windows CMD. Have Git, Python 3.12 with the `py` launcher, and GitHub Copilot CLI installed. Copilot needs its own account/access and login setup.

### 1. Clone

```bat
git clone https://github.com/boadadf/secret_keeper.git
cd secret_keeper
```

This README describes the files after merging Patch 08 with the earlier releases. If a script is missing from your checkout, that patch has not been published/merged there yet.

### 2. Prepare the standalone proxy

```bat
scripts\setup-proxy.cmd
```

The setup script creates `.venv` if absent, installs `mitmproxy` and `pytest` from `requirements-proxy.txt`, and initializes a private policy from the public fictional example only if the private policy does not already exist.

This is the standalone addon workflow. It does not install or verify the separate project CLI/package. For development of the full package, review `pyproject.toml` and use the declared development dependencies, for example:

```bat
.venv\Scripts\python.exe -m pip install -e ".[dev]"
```

Runtime dependencies in the new minimal requirements file are not pinned. A tested/pinned release dependency set remains work to complete.

### 3. Review your policy

```bat
notepad "%LOCALAPPDATA%\SecretKeeper\secret-keeper-policy.json"
```

It starts with fictional example values. Replace/merge values for your needs locally, not in the public example. The canary is disabled by default; some uncertain candidate detectors are audit-only.

An empty `rules` list allows inspectable content. Do not mistake it for protection.

### 4. Start the proxy — first CMD window

```bat
scripts\capture-requests.cmd
```

Leave it running. It listens on `127.0.0.1:8080` and creates certificate state under `%LOCALAPPDATA%\SecretKeeper` if needed. Its historical filename is retained; capture is OFF unless you enable it.

Stop older proxy processes first. Stop this one with `Ctrl+C`.

### 5. Start Copilot through the proxy — second CMD window

From the same checkout:

```bat
scripts\start-copilot.cmd
```

This wrapper sets `HTTP_PROXY`, `HTTPS_PROXY`, and `NODE_EXTRA_CA_CERTS` for the launched client process. The certificate file is `%LOCALAPPDATA%\SecretKeeper\mitmproxy-ca-cert.pem`, created when the proxy starts.

The wrapper overrides these proxy/certificate variables inside its own process only. If you require existing extra certificate bundles or corporate proxy settings, have an administrator review/merge them instead of blindly using this wrapper.

Trust only the CA from your own intended proxy. Do not set `NODE_TLS_REJECT_UNAUTHORIZED=0` or disable upstream certificate checks. Do not share the proxy CA private key. The wrapper does not change system-wide certificate trust.

Different client versions/builds can handle proxies differently. The synthetic block test below is required to confirm your client is actually routed and inspected; merely starting both programs is not proof.

### 6. Check normal behavior

In a fresh conversation:

```text
Reply with hello.
```

It should pass. Then test the enabled credential-assignment rule with synthetic content:

```text
password = "Synthetic-Only-42"
```

It should produce a block record. A HTTP block returns local status 422. A WebSocket block drops the outgoing message. The client may display an error or retry; improving that UX remains unfinished.

Start a fresh conversation after a blocking test. Sensitive content may remain in carried history and legitimately block later harmless prompts.

## Read the data being sent

Default audit logs do NOT contain prompts. Enable full capture only when you deliberately want to save attempted outgoing content, including rejected content.

Stop the proxy, then in its CMD window:

```bat
set "SECRET_KEEPER_CAPTURE_MODE=full"
scripts\capture-requests.cmd
```

Expect `FULL CAPTURE ACTIVE`. The launcher writes:

```text
%LOCALAPPDATA%\SecretKeeper\captures\outbound.jsonl
%LOCALAPPDATA%\SecretKeeper\captures\outbound.jsonl.txt
```

The first is the machine-readable record. The second is designed for people: separate records, clear decisions, expanded JSON fields/arrays, and wrapped text rather than one giant line.

Open the readable file:

```bat
notepad "%LOCALAPPDATA%\SecretKeeper\captures\outbound.jsonl.txt"
```

Example layout:

```text
OUTGOING PAYLOAD — HTTP — BLOCK
Time: ...
Flow: ...
Stage: attempted outbound content; ALLOW does not prove destination receipt.
Rules: credential-assignments

CONTENT:
  messages:
    [0]
      role:
        user
      content:
        password = "Synthetic-Only-42"
```

Capture and inspection are independent. Turning capture on does not permit blocked content to forward. `ALLOW` means the proxy permitted forwarding, not proof that the server received the data.

### View older JSONL captures

```bat
scripts\read-capture.cmd
```

Or select a file and filter:

```bat
scripts\read-capture.cmd "%LOCALAPPDATA%\SecretKeeper\captures\outbound.jsonl" --decision BLOCK
scripts\read-capture.cmd "%LOCALAPPDATA%\SecretKeeper\captures\outbound.jsonl" --transport websocket
```

Create a NEW local text file from an existing JSONL file:

```bat
scripts\read-capture.cmd "%LOCALAPPDATA%\SecretKeeper\captures\outbound.jsonl" --output "%LOCALAPPDATA%\SecretKeeper\captures\review.txt"
```

The viewer refuses to overwrite an existing output file. Conversion is local; no payload is uploaded. You can view rotated JSONL files in the same way.

### Turn capture off

Stop the proxy and run:

```bat
set "SECRET_KEEPER_CAPTURE_MODE=off"
scripts\capture-requests.cmd
```

Disabling capture does not remove existing files.

### Capture options and limits

Options belong to the proxy command, NOT the rule-policy JSON:

| Option | Default |
|---|---|
| `capture_mode` | `off`; use `full` explicitly |
| `capture_file` | Required dedicated JSONL path for full mode |
| `capture_readable` | `true` when full capture is enabled |
| `capture_readable_file` | JSONL path plus `.txt` unless specified |
| `capture_max_payload_bytes` | 1 MiB per raw/text representation |
| `capture_max_file_bytes` | 16 MiB per output file |
| `capture_backups` | 3 per output file |

JSONL and readable files rotate independently. Up to four files per format are retained by default; with two formats, the configured newly written storage budget can reach roughly 128 MiB. Old/pre-existing oversized files need separate review. Rotation deletes oldest backups, so this is not an indefinite archive.

Large captures are truncated and flagged. Readable formatting also has explicit display-depth/node/character limits. JSONL remains the primary record of captured bytes, itself subject to capture limits. Binary/non-UTF-8 data is summarized rather than dumped as huge Base64 text; its captured bytes remain in JSONL. No decompression, file extraction, or image inspection is added by the viewer.

`CAPTURE ERROR` means capture configuration failed and capture is disabled. `CAPTURE WRITE FAILED` means an output record was not guaranteed written. Check both outputs when diagnosing failures. Enforcement is not intentionally disabled by capture errors.

Full capture may contain passwords, customer information, source code, and previous context. There is no encryption, redacted mode, automatic age expiry, secure erasure, or cloud upload. Restrict Windows folder access, keep files out of Git, and remove them after analysis. One writer per capture file; synchronous capture adds disk latency.

## Rule configuration

Version-1 policies remain accepted. Version 2 supports per-rule controls:

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
          "values": ["Northstar Manufacturing"]
        }
      ]
    }
  ]
}
```

Rule IDs are logged; use opaque IDs, not confidential names. They must be unique lowercase letters/digits/hyphens/underscores, up to 64 characters. Invalid settings and duplicate IDs produce a policy error.

| Type | Purpose |
|---|---|
| `dictionary` | Registered names/phrases with normalization and boundaries |
| `exact_text` | Case-sensitive literal substring |
| `url_domain` | Configured hosts/subdomains in URLs inside content |
| `email` | Registered domains/addresses |
| `ip_network` | Canonical configured IPv4/IPv6 CIDRs |
| `field` | Registered JSON fields and exact values; empty values means any nonempty/non-redacted scalar |
| `resource` | Registered literal resource strings |
| `builtin` | Select a named detector |

Actions: `block` rejects; `audit` records and allows unless another rule blocks; disabled rules do not match. Any block wins. Rules operate over the whole inspected payload, not just the latest prompt.

Built-in names:

```text
credential_assignment
credential_field
private_key_block
supported_token_format
connection_string
credit_card
iban
phone_candidate
hash_candidate
entropy_candidate
```

They detect supported patterns, not authentic/active credentials or accounts. Some overlap. Phone detection is shape-only. Hash/entropy candidates do not prove confidentiality; the example uses audit mode for uncertain categories.

See the example policy and prior patch documentation for each type's fields. Add aliases explicitly; dictionary matching does not infer names.

### Canary test

Add/enable this rule in your private policy:

```json
{
  "id": "synthetic-canary",
  "type": "exact_text",
  "enabled": true,
  "action": "block",
  "value": "SECRET_KEEPER_CONFIDENTIAL_CANARY"
}
```

Restart, create a fresh client conversation, check `hello`, then send the full marker. It should block. Disable after testing if not wanted. Discard the test conversation because the marker may be included in later context.

### Inspection settings

The example enables bounded percent/hex/Base64 decoding up to two layers. Old policies without `inspection` settings default to decoding disabled. Limits constrain input size, JSON depth, views, decoding depth, and decoded bytes.

Default inspected text limit is 2 MiB, distinct from the launcher's 10 MiB transport body limit and capture caps. Exceedance produces `inspection_limit`. These are not complete CPU/resource or fail-closed guarantees.

## Paths and overrides

| Item | Default |
|---|---|
| Private state | `%LOCALAPPDATA%\SecretKeeper` |
| Private policy | State directory + `secret-keeper-policy.json` |
| Audit | State directory + `logs\audit.jsonl` |
| Capture | State directory + `captures\outbound.jsonl` |
| Readable capture | Capture path + `.txt` |

Set `SECRET_KEEPER_STATE` or `SECRET_KEEPER_POLICY` before running scripts to override defaults. Set the same custom state in both proxy and Copilot CMD windows. Reuse existing CA state for established clients.

## Tests and verification status

From CMD:

```bat
.venv\Scripts\python.exe -m pytest -q tests\unit\test_request_capture.py tests\unit\test_payload_capture.py tests\unit\test_readable_capture.py
scripts\test-proxy-integration.cmd
.venv\Scripts\python.exe tests\integration\run_rule_modes.py
scripts\test-expanded-rules.cmd
```

Earlier suites have 70 rule tests. This patch's 17 updated capture-helper and 18 formatting/viewer tests passed during generation; run the full installed suite too. The network suites expect 12, 16, and 64 checks respectively and require their earlier helper files.

The maintainer previously verified local rule blocking, the initial 12 network checks, and capture behavior. Patch 08's formatter/viewer tests are executed during generation. Its new CMD scripts, current repository contents, fresh Windows clone, Copilot routing, and combined/network regressions require Windows validation. Do not claim a clean-clone end-to-end test from Linux-only helper tests.

The network suites check real local HTTP/WS server receipts with positive controls. Timeout is FAIL, not proof of rejection. They do not establish HTTPS/WSS certificate behavior or all client UX.

## Troubleshooting

| Problem | Check |
|---|---|
| Missing launcher/helper | Patch files not merged or extracted at wrong directory |
| Python/venv missing | Python 3.12 launcher and setup command |
| Port 8080 occupied | Stop the prior proxy instance |
| Copilot certificate error | Proxy started, correct CA file/state, client trust configuration |
| Canary does not block | Active policy, enabled rule, restart, actual client routing |
| Harmless prompt blocks | Rule metadata and carried context; try a genuinely fresh session |
| `policy_error` | Active file exists and schema/settings are valid |
| `inspection_error` / `inspection_limit` | Inspectability and configured limits, not proof of a secret |
| No readable file | Full capture enabled, Patch 08 helper present, warning/error messages |
| Viewer fails at final record | Capture may have been interrupted mid-write; retain original for review |

Do not fix TLS problems by disabling verification. Do not upload raw captures to troubleshoot; share safe audit metadata instead.

## Boundaries and publishing

Not covered: bypassed traffic, incoming WebSocket messages, actual request headers or URL/query fields, arbitrary binary/files/images, every token/encoding, cross-message secrets, indirect identities, complete admin/resource hardening, or all unexpected addon failures.

URL rules inspect URL text inside bodies; they are not destination allowlists. HTTP rejects use 422; WebSocket rejects drop the message. Client retries remain unfinished. No automatic redaction or LLM stage currently exists.

Keep real policies, certificate state/private keys, captures, logs, `.venv`, and private environment files out of Git. Public example is `config/secret-keeper-policy.example.json`; local `config/secret-keeper-policy.json` should be ignored. Ignore rules do not erase history.

Contribute safe synthetic fixtures, documented detector limits, allow/block cases, and false-positive examples. See `LICENSE` and `NOTICE` for terms/attribution.

## Next steps

Optional local semantic validation, clearer client rejection, broader testing, and deployment/data-retention hardening. These are planned, not current protection guarantees.
