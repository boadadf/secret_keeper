# Patch 08 — readable capture and standalone Windows quick start

Requires installed Patch 06 rules.py and Patch 07 request_capture.py. Replace the
capture helper, add readable formatter, viewer and CMD setup/client launch scripts.
New main README supplied. No rule-policy/example/source engine overwrite.

The existing addon calls capture.load/configure/write, so no entry-point edit needed.
Readable defaults true in full capture; output JSONL path + .txt. Old audit remains
metadata-only. New launcher defaults off and enables via SECRET_KEEPER_CAPTURE_MODE.
Restart for changed capture options (older addon live-update whitelist not expanded).

Existing installation: merge at ROOT, run viewer/format tests, rerun prior suites.
For clean users, commit these files with all preceding source/helper/example files.
Do not claim scripts present remotely until committed. setup-proxy is standalone
addon dependency setup, NOT complete pyproject package installation.

Runtime README covers clone/setup/private policy/proxy/client routing/capture viewing,
CA caveats, errors and safe retention. A fresh Windows clone/end-to-end run remains
pending: GitHub fetch unavailable, no Windows execution in generation environment.
New tests verify real formatter/capture writes/viewer subprocesses and basic layout;
static checks do not validate CMD execution or pip install on Windows.

Capture text/JSONL rotate independently; text display limits explicit. Sensitive
control characters escaped. Captures are NOT safe to publish. No LLM added.
