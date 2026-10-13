## Optional outbound text replacement

Secret Keeper can replace explicitly configured text before forwarding supported outbound content. For example, a customer name in a code comment can become `[CUSTOMER]` without modifying the local file.

Add this optional array alongside `rules` in your active schema-version-2 private policy:

```json
"replacements": [
  {
    "id": "mask-customer-name",
    "enabled": true,
    "find": "Customer AG",
    "replace_with": "[CUSTOMER]",
    "case_sensitive": false,
    "boundary": "whole_phrase"
  }
]
```

Explicit replacements run first, then existing block/audit rules inspect the modified content. Remaining blocking matches still reject. Policies without replacements preserve strict behavior; keep customer-name blockers as a fallback.

Supports literal replacement in plain text and selected JSON text fields in outbound HTTP/WebSocket payloads. Does not rewrite HTTP headers, local files, JSON keys, incoming answers, or arbitrary binary/signed content. See `docs/replacements.md` for scope, ordering, limits and testing.

Metadata-only audits show replacement IDs and counts. Optional full capture preserves original and modified/candidate stages, so original captures may still contain secrets. Keep using `scripts\capture-requests.cmd copilot`; restart after editing policy. Merge `config/secret-keeper-replacements.example.json` as needed; do not overwrite your private policy with it.
