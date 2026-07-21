#!/usr/bin/env bash
set -euo pipefail
# Add joern-cli to PATH (adjust if your joern lives elsewhere)
export PATH="$PATH:$HOME/bin/joern/joern-cli"

usage() {
  echo "Usage:" >&2
  echo "  $0 <jobs-file>" >&2
  echo "" >&2
  echo "  <jobs-file>: one flow per line, tab-separated:" >&2
  echo "    cpgPath<TAB>flowKey<TAB>sourceFile<TAB>sourceLine<TAB>sinkFile<TAB>sinkLine" >&2
  echo "  Flows sharing a cpgPath load that CPG only once." >&2
}

if [[ $# -ne 1 ]]; then
  usage
  exit 2
fi

JOBS_FILE="$1"

SCRIPT_DIR="$(
  cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &&
  pwd
)"
SCALA_SCRIPT="$SCRIPT_DIR/pdg_slice_batch.sc"

if ! command -v joern >/dev/null 2>&1; then
  echo "Error: 'joern' command not found in PATH" >&2
  exit 1
fi
if [[ ! -f "$JOBS_FILE" ]]; then
  echo "Error: jobs file not found: $JOBS_FILE" >&2
  exit 1
fi
if [[ ! -f "$SCALA_SCRIPT" ]]; then
  echo "Error: Joern script not found: $SCALA_SCRIPT" >&2
  exit 1
fi

JOBS_FILE="$(realpath "$JOBS_FILE")"

echo "=== Joern PDG Slice (batch: one session per jobs file) ==="
echo "Jobs file   : $JOBS_FILE"
echo "Scala script: $SCALA_SCRIPT"
echo

exec joern \
  --script "$SCALA_SCRIPT" \
  --param "jobsFile=$JOBS_FILE"
