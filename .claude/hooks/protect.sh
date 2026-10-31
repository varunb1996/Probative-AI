#!/usr/bin/env bash
# PreToolUse: block changes to THIS project's ground truth, hook config and import contracts.
# Protected (relative to the project root): eval/labels/, .claude/, .importlinter
# Files outside the project (e.g. the user-level ~/.claude used for plans and memory) are not touched.
# Handles edit tools, Bash and PowerShell; forward or back slashes; any letter case.
# Exit 2 blocks the tool call and shows stderr to Claude.

if ! command -v jq >/dev/null 2>&1; then
  echo "Blocked: jq is not installed, so protected paths cannot be checked. Ask the user to install jq." >&2
  exit 2
fi

input=$(cat)
if ! tool=$(printf '%s' "$input" | jq -r '.tool_name // empty' 2>/dev/null); then
  echo "Blocked: hook could not parse the tool call, so protected paths cannot be checked." >&2
  exit 2
fi

# Lowercase, backslashes to slashes, collapse repeats, /c/... to c:/...
norm() {
  printf '%s' "$1" | tr '[:upper:]' '[:lower:]' | sed -e 's#\\#/#g' -e 's#//*#/#g' -e 's#^/\([a-z]\)/#\1:/#'
}

PROJ=$(norm "${CLAUDE_PROJECT_DIR:-$PWD}"); PROJ=${PROJ%/}
REL_PROTECTED='^(eval/labels(/|$)|\.claude(/|$)|\.importlinter$)'

# Shell tools: a command is blocked if it names a protected path relative to the project
# (or by its absolute path inside the project) AND looks like a write.
if [[ "$tool" == "Bash" || "$tool" == "PowerShell" ]]; then
  cmd=$(norm "$(printf '%s' "$input" | jq -r '.tool_input.command // empty')")
  # Relative mentions must start a word ("./" allowed), so c:/users/varun/.claude is not matched.
  REL_IN_CMD="(^|[[:space:]\"'=(,;|&>])(\./)?(eval/labels(/|[[:space:]\"']|$)|\.claude(/|[[:space:]\"']|$)|\.importlinter)"
  ABS_IN_CMD="$(printf '%s' "$PROJ" | sed 's#[.[\*^$()+?{|]#\\&#g')/(eval/labels|\.claude|\.importlinter)"
  WRITES='(>|\brm\b|\bmv\b|\bcp\b|\btee\b|\btouch\b|\bln\b|\bmkdir\b|sed -i|truncate|chmod|attrib|icacls|open\(|git (checkout|restore|rm|reset)'
  WRITES+='|set-content|add-content|out-file|clear-content|remove-item|move-item|copy-item|new-item|rename-item|set-item'
  WRITES+='|\b(sc|ac|ri|del|erase|rd|rmdir|mi|move|cpi|copy|ni|ren)\b|\[io\.file\]|writealltext|writealllines)'
  if { printf '%s' "$cmd" | grep -Eq "$REL_IN_CMD" || printf '%s' "$cmd" | grep -Eq "$ABS_IN_CMD"; } &&
     printf '%s' "$cmd" | grep -Eq "$WRITES"; then
    echo "Blocked: this command may modify a protected project path (eval/labels, .claude, .importlinter). Reading is fine; changes are the user's job." >&2
    exit 2
  fi
  exit 0
fi

# Edit tools: resolve the target relative to the project root.
path=$(norm "$(printf '%s' "$input" | jq -r '.tool_input.file_path // .tool_input.notebook_path // empty')")
[[ -z "$path" ]] && exit 0
if [[ "$path" =~ ^[a-z]:/ || "$path" == /* ]]; then
  case "$path" in
    "$PROJ"/*) rel=${path#"$PROJ"/} ;;
    *) exit 0 ;;   # outside the project: not ours to guard
  esac
else
  rel=${path#./}
fi
if printf '%s' "$rel" | grep -Eq "$REL_PROTECTED"; then
  echo "Blocked: $rel is protected (ground truth, hook config, or import contracts). Stop and tell the user what change you think is needed." >&2
  exit 2
fi
exit 0
