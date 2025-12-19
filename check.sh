#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"

make build
bash tests/test_basic.sh
