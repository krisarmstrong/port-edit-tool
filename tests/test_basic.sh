#!/bin/bash
# Basic smoke tests for port-edit-tool

set -e

echo "Running basic tests for port-edit-tool..."

# Test 1: Check if main script exists
echo "Test 1: Checking if main script exists..."
MAIN_SCRIPT=$(find . -name "*.py" -o -name "*.sh" | head -1)
if [ -n "$MAIN_SCRIPT" ]; then
    echo "  ✓ Main script found: $MAIN_SCRIPT"
else
    echo "  ✗ No main script found"
    exit 1
fi

# Test 2: Check for Python syntax if Python script
echo "Test 2: Checking syntax..."
if [[ "$MAIN_SCRIPT" == *.py ]]; then
    python3 -m py_compile "$MAIN_SCRIPT" && echo "  ✓ Python syntax check passed" || exit 1
elif [[ "$MAIN_SCRIPT" == *.sh ]]; then
    bash -n "$MAIN_SCRIPT" && echo "  ✓ Shell syntax check passed" || exit 1
fi

echo ""
echo "All tests passed! ✓"
