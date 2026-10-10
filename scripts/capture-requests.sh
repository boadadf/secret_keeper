#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
if ! command -v cmd.exe >/dev/null 2>&1; then
  printf 'ERROR: This launcher requires Windows with cmd.exe.\n' >&2
  exit 2
fi
if (( $# > 1 )); then
  printf 'Usage: capture-requests.sh [copilot|none]\n' >&2
  exit 2
fi
mode="${1:-copilot}"
case "$mode" in
  copilot|none) ;;
  *) printf 'ERROR: Expected copilot or none.\n' >&2; exit 2 ;;
esac
exec cmd.exe /c "scripts\capture-requests.cmd $mode"
