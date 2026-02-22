#!/bin/bash
set -euo pipefail

# Only run in remote (web) sessions
if [ "${CLAUDE_CODE_REMOTE:-}" != "true" ]; then
  exit 0
fi

cd "$CLAUDE_PROJECT_DIR"

# ── 1. Install project dependencies (Bun workspaces) ──
if command -v bun &>/dev/null; then
  bun install
fi

# ── 2. Install hyperpowers plugin ──
# Add the marketplace and install the plugin so it's actually downloaded,
# not just referenced in settings.json.
if command -v claude &>/dev/null; then
  claude plugin marketplace add withzombies/hyperpowers 2>/dev/null || true
  claude plugin install hyperpowers@withzombies --scope project 2>/dev/null || true
fi
