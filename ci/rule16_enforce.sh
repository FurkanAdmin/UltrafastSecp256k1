#!/usr/bin/env bash
# Rule 16 enforcement wrapper used by preflight.yml, gate.yml (shim-gate), and
# release.yml. Invokes ci/check_advisory_skip_returns.sh and treats:
#   rc=0  → notice  : all advisory modules return 77 (enforcement passed)
#   rc=77 → warning : no standalone advisory binaries built in this configuration
#                     (legitimate skip — the build only produces unified_audit_runner
#                     and not the per-module standalone executables that the
#                     script enumerates). Enforcement is exercised in build
#                     configurations that DO produce standalone targets.
#   rc=*  → error   : at least one advisory module returned a non-77 non-zero
#                     value (Rule 16 violation: rc=0 = silent false PASS).
#
# Extracted 2026-05-24 to remove the identical inline wrapper across three
# workflows (SonarCloud Quality Gate flagged "9.1% duplication on new code").
set +e
bash "$(dirname "$0")/check_advisory_skip_returns.sh"
rc=$?
set -e
if [ "$rc" -eq 0 ]; then
    echo "::notice::Rule 16: all advisory modules return 77 (enforcement passed)"
elif [ "$rc" -eq 77 ]; then
    echo "::warning::Rule 16: no standalone advisory binaries built in this configuration; gate soft-skipped"
else
    echo "::error::Rule 16: at least one advisory module returned 0 instead of 77"
    exit "$rc"
fi
