#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

if ! command -v cmd.exe >/dev/null 2>&1; then
  printf 'ERROR: This launcher requires Windows with cmd.exe.\n' >&2
  exit 2
fi

exec cmd.exe /c 'scripts\capture-requests.cmd'