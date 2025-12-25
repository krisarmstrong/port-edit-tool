#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"

# Build to verify compilation
make build
