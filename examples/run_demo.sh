#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 The OmniSeek Authors
#
# OmniSeek in one minute, with no install: scan the deliberately flawed demo app, render every
# report format, then verify a findings file that contains model-style mistakes.
#
#   bash examples/run_demo.sh [OUTPUT_DIR]
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(dirname "$HERE")"
OUT="${1:-$(mktemp -d "${TMPDIR:-/tmp}/omniseek-demo.XXXXXX")}"
mkdir -p "$OUT"
PY="${PYTHON:-python3}"
export PYTHONPATH="$ROOT${PYTHONPATH:+:$PYTHONPATH}"
APP="$HERE/vulnerable_app"

echo "1. Scan the demo app (four lenses, deterministic, offline)"
"$PY" -m omniseek scan "$APP" --output "$OUT/findings.json" --html "$OUT/dossier.html" \
  --sarif "$OUT/omniseek.sarif" --markdown "$OUT/report.md"

echo
echo "2. Verify the scan: every citation must check out"
"$PY" -m omniseek verify "$OUT/findings.json" --repo "$APP"

echo
echo "3. Verify model-style findings with a drifted and a hallucinated citation (expected to be flagged)"
set +e
"$PY" -m omniseek verify "$HERE/sample_findings.json" --repo "$APP" --output "$OUT/sample_verified.json"
code=$?
set -e
if [ "$code" -ne 1 ]; then
  echo "unexpected exit code $code: the planted mistakes should fail the default --min-score 1.0 gate" >&2
  exit 1
fi
"$PY" -m omniseek report "$OUT/sample_verified.json" --format html --output "$OUT/sample_dossier.html"

echo
echo "4. Preview what cloud-sync would send (nothing is sent)"
"$PY" -m omniseek cloud-sync "$OUT/findings.json" --dry-run --no-snippets >"$OUT/cloud_payload.json"

echo
echo "Done. Open $OUT/dossier.html and $OUT/sample_dossier.html"
