#!/usr/bin/env bash
# Reproduces the reference (known-answer) audit run: wolfSSL v5.9.0-stable,
# wolfcrypt/src/dilithium.c, dilithium_sign_with_seed_mu.
#
# Issue #319: goes through the task-file interface (python -m
# pqc_reduction_audit.cli --task <file> --out-dir <dir>), the same form any
# other queued run uses, instead of a one-off pile of --flags. The
# known-answer self-check now lives IN the run's own result.json
# (known_answer_check), so a non-zero CLI exit on mismatch is enough --
# there is no longer a separate external diff step here.
#
# The target source is fetched fresh into a temp directory and never
# committed to this repository (license constraint, see README.md).
#
# Usage: bash pqc_reduction_audit/run_known_answer.sh
set -euo pipefail

TAG="v5.9.0-stable"
REPO_URL="https://github.com/wolfSSL/wolfssl.git"
RUN_LABEL="KNOWN_ANSWER_WOLFSSL_DILITHIUM_SMALL"
REFERENCE="results/pqc_audit_run/${RUN_LABEL}.json"

WORKDIR="$(mktemp -d)"
trap 'rm -rf "$WORKDIR"' EXIT

echo "Fetching wolfSSL ${TAG} into ${WORKDIR}..."
git clone --depth 1 --branch "$TAG" --quiet "$REPO_URL" "$WORKDIR/wolfssl"

TARGET="$WORKDIR/wolfssl/wolfcrypt/src/dilithium.c"
if [ ! -f "$TARGET" ]; then
    echo "ERROR: expected file not found at $TARGET -- has the wolfSSL repo layout changed?" >&2
    exit 1
fi

# The known-answer sites below are the same three the committed reference
# report (results/pqc_audit_run/KNOWN_ANSWER_WOLFSSL_DILITHIUM_SMALL.json)
# already records -- kept in sync by hand, same as before this refactor.
TASK_FILE="$WORKDIR/task.json"
cat > "$TASK_FILE" <<JSON
{
  "library": "wolfSSL",
  "version": "${TAG}",
  "target_file": "wolfcrypt/src/dilithium.c",
  "include_root": "$WORKDIR/wolfssl",
  "function": "dilithium_sign_with_seed_mu",
  "target_profile": "wolfssl",
  "defines": ["HAVE_DILITHIUM", "WOLFSSL_WC_DILITHIUM"],
  "run_label": "${RUN_LABEL}",
  "known_answer": {
    "expected_sites": [
      {"label": "w0 = w - cs2 (Step 22, FIPS 204 Algorithm 2)", "is_defect": true},
      {"label": "z = y + cs1 (Step 21, FIPS 204 Algorithm 2)", "is_defect": false},
      {"label": "ct0 = NTT-1(c o t0) (Step 25/27, FIPS 204 Algorithm 2)", "is_defect": true}
    ]
  }
}
JSON

OUT_DIR="$WORKDIR/audit_out"
echo "Running audit (task-file form, output: $OUT_DIR, not results/pqc_audit_run/)..."
python3 -m pqc_reduction_audit.cli --task "$TASK_FILE" --out-dir "$OUT_DIR"
# --task exits non-zero on its own if known_answer_check.passed is false --
# `set -e` above already stops the script there with a clear CLI message.

LOCAL_JSON="$OUT_DIR/${RUN_LABEL}.json"

echo ""
echo "✓ Known-answer self-check passed (see above)."
if [ -f "$REFERENCE" ]; then
    # Secondary check, informational only: sites + target_version.sha256
    # (the fields that existed before Issue #319) should still match the
    # committed reference byte-for-byte -- task/auditor_version/run_seconds
    # are new and expected to differ (a fresh commit, a fresh timer).
    python3 - "$REFERENCE" "$LOCAL_JSON" <<'PY'
import json, sys
ref = json.load(open(sys.argv[1], encoding="utf-8"))
local = json.load(open(sys.argv[2], encoding="utf-8"))
ok = (ref["sites"] == local["sites"]
      and ref["target_version"]["sha256"] == local["target_version"]["sha256"])
if ok:
    print(f"✓ sites + target_version.sha256 match the committed reference byte-for-byte ({sys.argv[1]})")
else:
    print(f"✗ sites or target_version.sha256 differ from the committed reference {sys.argv[1]}")
    sys.exit(1)
PY
else
    echo "⚠ No committed reference at $REFERENCE -- nothing to compare against."
    echo "  Local run report: $LOCAL_JSON"
fi
