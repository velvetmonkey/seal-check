#!/bin/bash
# Terminal-capturable showcase for seal-check: runs the receipt verify test which prints PASS/FAIL for genuine and tampered cases.
set -euo pipefail
cd "$(dirname "$0")/.."
node test/receipt-verify.test.cjs
