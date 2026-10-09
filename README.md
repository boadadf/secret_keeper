# Secret Keeper

Local outbound content-policy enforcement for AI-client traffic.

Secret Keeper is an experimental mitmproxy addon that inspects buffered HTTP request bodies and outgoing WebSocket payloads before forwarding them. It can reject configured names, synthetic canaries, and selected secret-like content.

It is not a complete data-loss prevention system, an endpoint firewall, or a guarantee that confidential information cannot leave a machine. Only traffic routed through the proxy and covered by its inspection logic is evaluated.

## Current status

The current prototype is Patch 04. The maintainer reports successful live Copilot rule tests, including canary enforcement. The supplied addon test suite contains 21 synthetic tests. These do not establish controlled-upstream non-receipt or verify every client, transport, and detector combination.

Known unfinished work includes controlled HTTP/WebSocket upstream tests, clearer client-facing rejection, retry handling, deployment hardening, and CMD launchers. These are planned, not shipped capabilities.

## Features

- Configurable dictionary of forbidden names, phrases, aliases, and identifiers.
- Case folding, Unicode NFKC normalization, and whitespace normalization for dictionary matching.
- Whole-phrase and substring dictionary boundaries.
- Opt-in exact synthetic canary: `SECRET_KEEPER_CONFIDENTIAL_CANARY`.
- Selected credential assignments and named JSON credential fields.
- Paired private-key blocks.
- Limited legacy GitHub token and AWS access-key-ID formats.
- Buffered HTTP body inspection and outgoing UTF-8 WebSocket payload inspection.
- Metadata-only audit records; enforcement does not depend on audit logging being enabled.

AWS access-key IDs are identifiers, not the associated secret keys. Pattern matches indicate potential sensitive content, not verified active credentials.

## Requirements and setup

The demonstrated workflow uses Windows CMD, a Python virtual environment, mitmproxy, and pytest for tests. The addon imports mitmproxy and the Python standard library.

For an isolated prototype environment, from the repository root:

```bat
py -m venv .venv
.venv\Scripts\python.exe -m pip install mitmproxy pytest
```

If the repository provides pinned dependency files, use those instead. This README does not establish a supported Python/mitmproxy version matrix or a complete application installation procedure.

HTTPS interception requires the client to trust the proxy's CA. Follow an approved certificate setup for your environment. Do not commit the CA private key or disable upstream TLS verification to bypass certificate problems. Clients may require explicit proxy settings or have certificate-pinning restrictions; starting the proxy does not automatically route their traffic through it.

## Private configuration

Keep the real policy outside the checkout. Customer dictionaries and internal identifiers are confidential deployment data.

In CMD:

```bat
set "STATE=%LOCALAPPDATA%\SecretKeeper"
set "POLICY=%LOCALAPPDATA%\SecretKeeper\secret-keeper-policy.json"
set "LOG=%LOCALAPPDATA%\SecretKeeper\logs\audit.jsonl"
if not exist "%STATE%" mkdir "%STATE%"
notepad "%POLICY%"
```

For an existing installation, reuse the certificate-state directory already trusted by your client. Creating a different directory may create different CA material requiring a separate trust setup.

Save this minimal policy:

```json
{
  "schema_version": 1,
  "canary_enabled": false,
  "secrets_enabled": true,
  "dictionary": []
}
```

The addon also defaults to `config/secret-keeper-policy.json` when no explicit policy path is supplied. The public release should contain only a safe example policy; private local policies must not be tracked.

Policy edits require a proxy restart. Missing or invalid policies block requests with `policy_error`. A new policy path is not automatically populated.

### Dictionary example

Use fictional entries for testing:

```json
{
  "schema_version": 1,
  "canary_enabled": false,
  "secrets_enabled": true,
  "dictionary": [
    {
      "id": "test-customer-001",
      "values": [
        "Northstar Manufacturing",
        "Northstar Manufacturing GmbH"
      ],
      "boundary": "whole_phrase"
    }
  ]
}
```

Each entry must have exactly `id`, `values`, and `boundary`. IDs must be unique opaque lowercase letters, digits, hyphens, or underscores, up to 64 characters. Values must contain at least three normalized characters. Boundary is `whole_phrase` or `substring`.

IDs are logged: do not use confidential customer names as IDs. Whole-phrase matching uses Unicode word boundaries; punctuation and filenames need deliberate test coverage. Substring matching can create more false positives.

## Run the proxy in CMD

From the repository root, in the same CMD window where the variables above were set:

```bat
.venv\Scripts\mitmdump.exe --mode regular --listen-host 127.0.0.1 --listen-port 8080 --set "confdir=%STATE%" --set ssl_insecure=false --set flow_detail=0 --set termlog_verbosity=error --set connection_strategy=lazy --set body_size_limit=10m -s src\secret_keeper\request_capture.py --set "request_log=%LOG%" --set "secret_keeper_policy=%POLICY%"
```

Keep the filename `request_capture.py`: despite its historical name, it now performs inspection and enforcement. The log is metadata-only in Patch 04.

Use a second CMD window to run your AI client with its existing working proxy and certificate configuration. This README does not claim a universal Copilot configuration command. Keep port 8080 free by stopping any earlier proxy instance.

The 10 MB setting is an operational body limit, not a complete resource-control or no-leak guarantee. Error verbosity hides informational startup messages; block and policy-error messages remain visible.

## Test

### Automated addon tests

```bat
.venv\Scripts\python.exe -m pytest -q tests\unit\test_request_capture.py
```

For the unchanged Patch 04 test file, expect 21 passing tests. Tests substitute mitmproxy objects and validate decisions and hook calls, not actual network forwarding. Run the full repository suite separately where applicable.

### Live allow/block checks

Use only synthetic credentials and fictional customers. Start a fresh session for each blocking case.

| Input | Expected outcome |
| --- | --- |
| `Reply with hello.` | Allow |
| `Explain how passwords work.` | Allow |
| `Explain what an API key is.` | Allow |
| `password = "Synthetic-Only-42"` | Block: credential assignment |
| `{"client_secret":"Synthetic-Only-42"}` | Block: credential assignment or field |
| `Northstar Manufacturing` | Block only when the example dictionary is loaded |
| `Northstar` | Allow under the example whole-phrase dictionary |

For the canary test, set `canary_enabled` to `true`, restart the proxy, and start a fresh client session. First check that `Reply with hello.` passes, then send:

```text
Reply with exactly: SECRET_KEEPER_CONFIDENTIAL_CANARY
```

Expect a `test_canary` block. Disable the canary afterward unless you want the synthetic detector active.

The entire inspected payload is checked, not only the latest prompt. A marker or secret in conversation history, attached context, or tool output can block a subsequent harmless prompt. Do not resume a contaminated test conversation when checking normal behavior.

### Verification still required

Controlled upstream integration tests must confirm that allowed content arrives and rejected HTTP bodies/WebSocket messages do not. A local block log alone does not prove non-receipt. Authentication and protocol metadata may still be exchanged.

## Blocking behavior

HTTP rejection produces a local 422 JSON response containing `secret_keeper_blocked`. The client may display its own error or retry. This is not a verified provider-compatible rejection format.

Outgoing WebSocket rejection drops the message. The client may wait, time out, or retry because no compatible application-level error is injected. Retry UX is unresolved.

No automatic redaction is performed. Changing text silently is intentionally not part of the current prototype.

## Audit and troubleshooting

Audit records contain timestamp, flow ID, transport, decision, rule ID, optional opaque dictionary entry ID, and numeric structural location. They omit payloads, matched values, URL paths, headers, and JSON field names.

| Rule ID | Meaning |
| --- | --- |
| `test_canary` | Exact enabled test marker matched |
| `dictionary` | Configured dictionary entry matched |
| `credential_assignment` | Text assignment matched |
| `credential_field` | Named JSON credential field contained a non-placeholder string |
| `private_key_block` | Paired private-key delimiters matched |
| `supported_token_format` | One of the implemented token/identifier formats matched |
| `policy_error` | Policy unavailable or invalid |
| `inspection_error` | Content could not be inspected |
| `body_unavailable` | Buffered HTTP body unavailable |

`body.text` means JSON parsing did not succeed and matching ran on text. It is not evidence that the newest prompt contained the match. Structural locations use numeric positions to avoid exposing user-controlled JSON keys.

Earlier capture versions stored bodies. Patch 04 does not erase existing logs: protect or securely dispose of previous capture files according to your retention policy. Windows filesystem ACLs and access controls require deployment-specific review. Logs have no built-in rotation in this prototype.

## Security boundaries and limitations

- Only routed, successfully intercepted traffic is covered.
- Headers and URL/query parameters are not inspected by Patch 04.
- No Base64 decoding, image/OCR inspection, arbitrary binary protocol parsing, or cross-message reassembly.
- WebSocket payloads must decode as UTF-8; uninspectable payloads block.
- No general bare-password or semantic confidentiality detector.
- Token patterns cover a limited subset, not every provider or token generation.
- Credential examples, code snippets, and legitimate protocol fields may create false positives.
- Legitimate authentication headers are not scanned; they are not a general bypass for secrets in bodies.
- Unexpected addon exceptions and load failures are not a hardened fail-closed boundary.
- Policy administration, resource bounds, long-lived WebSocket retention, and log lifecycle need hardening.
- Dictionaries cannot guarantee that an identity is never disclosed indirectly or through unregistered aliases.

Do not deploy this prototype as your sole confidentiality control or claim universal no-leak protection.

## Contributing and publishing safely

Contributions should include allow and block tests, false-positive cases, safe fixtures, and an accurate description of transport coverage. Never submit real customer names, tokens, passwords, private keys, or raw traffic in issues or pull requests.

Before pushing, inspect staged changes and repository history. Keep local policies, `.venv`, `.env` files, logs, captures, and CA state out of Git. Ignore rules do not remove previously committed content. Rotate exposed credentials and assess history cleanup when necessary.

The repository should ship a fictional or empty example configuration rather than a company's deployed dictionary. Any new features must be documented as implemented, tested, or planned without conflating those states.

## Roadmap

- Controlled HTTP and WebSocket upstream integration tests.
- CMD launchers and safe first-run policy initialization.
- Public/private configuration packaging.
- Better safe request classification and match diagnostics.
- Verified client-facing rejection and retry behavior.
- Expanded format detectors with documented false-positive tradeoffs.
- Deployment hardening and administrator-managed policies.

## License

Check the repository's `LICENSE` file for applicable terms. No license choice is asserted by this README. Select and include an explicit license before describing the release as open source.
