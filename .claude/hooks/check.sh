#!/usr/bin/env bash
# PostToolUse: after a Python edit, check module boundaries, then tests.
# Exit 2 feeds the failure back to Claude so it fixes it before moving on.

command -v jq >/dev/null 2>&1 || exit 0
path=$(cat | jq -r '.tool_input.file_path // empty')
[[ "$path" == *.py ]] || exit 0

cd "$CLAUDE_PROJECT_DIR" || exit 0

# Before Phase 1 there is no triage package, so there are no boundaries to check yet.
if [[ -f triage/__init__.py ]]; then

# Fail loudly if the boundary checker is missing: a silent skip would let contracts break unnoticed.
if ! command -v lint-imports >/dev/null 2>&1; then
  echo "lint-imports not found on PATH, so module boundaries were NOT checked. Ask the user to fix PATH (see docs/build-prompts.md setup)." >&2
  exit 2
fi
if ! out=$(lint-imports 2>&1); then
  printf 'Import contract broken. Do not edit .importlinter; fix the import or ask the user.\n%s\n' "$(printf '%s' "$out" | tail -30)" >&2
  exit 2
fi

fi

# During a red (tests-first) phase the user creates .claude/red-phase by hand,
# so expected failures do not block. Claude cannot create it (protect.sh).
[[ -f .claude/red-phase ]] && exit 0

out=$(python -m pytest -q -x 2>&1); rc=$?
# rc 5 = no tests collected yet; not a failure.
if [[ $rc -ne 0 && $rc -ne 5 ]]; then
  printf 'Tests failing. Fix the code, not the test.\n%s\n' "$(printf '%s' "$out" | tail -40)" >&2
  exit 2
fi
exit 0
