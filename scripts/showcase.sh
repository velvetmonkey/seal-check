#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")/.."
exec node test/receipt-verify.test.cjs 2>&1
