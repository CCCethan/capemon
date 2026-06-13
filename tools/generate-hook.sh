#!/usr/bin/env bash
# Generate a capemon hook using Claude Code CLI (Claude Pro auth — no API key needed).
#
# Usage:
#   ./tools/generate-hook.sh <ApiName> <library> <category> "<evasion description>"
#
# Example:
#   ./tools/generate-hook.sh NtQuerySystemInformation ntdll system \
#       "Malware calls NtQuerySystemInformation(SystemProcessorInformation) to read CPU count"
#
# Output: three labeled C code blocks printed to stdout.
# Pipe to a file or paste into the relevant source files.

set -euo pipefail

if [ "$#" -lt 4 ]; then
    echo "Usage: $0 <ApiName> <library> <category> \"<evasion description>\"" >&2
    exit 1
fi

API="$1"
LIB="$2"
CAT="$3"
DESC="$4"

ARGS="$API $LIB $CAT \"$DESC\""

COMMANDS_DIR="$(cd "$(dirname "$0")/.." && pwd)/.claude/commands"
PROMPT_FILE="$COMMANDS_DIR/generate-hook.md"

if [ ! -f "$PROMPT_FILE" ]; then
    echo "ERROR: prompt file not found at $PROMPT_FILE" >&2
    exit 1
fi

PROMPT=$(sed "s|\\\$ARGUMENTS|$ARGS|g" "$PROMPT_FILE")

exec claude --print "$PROMPT"
