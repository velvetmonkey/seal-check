#!/bin/bash
set -euo pipefail
ALLOWED="README.md FINDINGS.md scripts/showcase.sh scripts/capture_evidence.sh scripts/verify_glowup_scope.sh"
CHANGED=$(git diff --name-only HEAD~1..HEAD 2>/dev/null || git diff --name-only --cached 2>/dev/null || echo '')
for f in $CHANGED; do
  if [[ "$f" == "scripts/verify_glowup_scope.sh" ]]; then continue; fi
  ok=0
  for a in $ALLOWED; do
    if [[ "$f" == "$a" ]]; then ok=1; break; fi
  done
  if [[ $ok -eq 0 ]]; then
    echo "ERROR: $f not allowed in glowup diff"
    exit 1
  fi
done
echo "scope OK: only allowed files"
