#!/bin/bash
set -euo pipefail
REPO="seal-check"
SCRATCH="${SCRATCH:-/tmp/grok-goal-812b560f73c6/implementer}"
mkdir -p "$SCRATCH"
BRANCH_LOG="$SCRATCH/${REPO}-branch.log"
DEMO_LOG="$SCRATCH/${REPO}-demo.log"
: > "$DEMO_LOG"
if [[ -n "$(git status --porcelain)" ]]; then
  echo "ERROR: working tree not clean"
  git status --porcelain
  exit 1
fi
{
  echo "BRANCH:"
  git branch --show-current
  echo "PORCELAIN:"
  git status --porcelain
  echo "PORCELAIN_END"
  echo "COMMIT_LOG:"
  git log --oneline -3
  echo "TIP_STAT:"
  git show --stat HEAD
} > "$BRANCH_LOG"
CMD="bash scripts/showcase.sh"
echo "RUNNING: $CMD"
if timeout 30s bash -c "$CMD" > >(tee -a "$DEMO_LOG") 2>&1 ; then
  echo "=== capture succeeded ==="
  exit 0
else
  echo "=== capture failed ==="
  exit 1
fi
