#!/usr/bin/env bash
set -euo pipefail

# ─── ClawPinch common helpers ───────────────────────────────────────────────
# Source this file from any scanner:
#   source "$(dirname "$0")/helpers/common.sh"

# ─── Logging ────────────────────────────────────────────────────────────────

_CLR_RED='\033[0;31m'
_CLR_YLW='\033[0;33m'
_CLR_BLU='\033[0;34m'
_CLR_GRN='\033[0;32m'
_CLR_DIM='\033[2m'
_CLR_RST='\033[0m'

log_info()  { printf "${_CLR_BLU}[info]${_CLR_RST}  %s\n" "$*" >&2; }
log_warn()  { printf "${_CLR_YLW}[warn]${_CLR_RST}  %s\n" "$*" >&2; }
log_error() { printf "${_CLR_RED}[error]${_CLR_RST} %s\n" "$*" >&2; }

# ─── Command detection ──────────────────────────────────────────────────────

has_cmd() {
  command -v "$1" &>/dev/null
}

require_cmd() {
  if ! has_cmd "$1"; then
    log_error "Required command not found: $1"
    return 1
  fi
}

# ─── OS detection ───────────────────────────────────────────────────────────

detect_os() {
  case "$(uname -s)" in
    Darwin*) echo "macos" ;;
    Linux*)  echo "linux" ;;
    *)       echo "unknown" ;;
  esac
}

# ─── OpenClaw config helpers ────────────────────────────────────────────────

get_openclaw_config() {
  local config_dir="${CLAWPINCH_CONFIG_DIR:-}"

  # If explicit config dir was provided, use it
  if [[ -n "$config_dir" ]]; then
    if [[ -f "$config_dir/openclaw.json" ]]; then
      echo "$config_dir/openclaw.json"
      return 0
    elif [[ -f "$config_dir/config.json" ]]; then
      echo "$config_dir/config.json"
      return 0
    fi
  fi

  # Auto-detect common locations
  local os
  os="$(detect_os)"
  local search_paths=()

  if [[ "$os" == "macos" ]]; then
    search_paths=(
      "$HOME/.config/openclaw/openclaw.json"
      "$HOME/.config/openclaw/config.json"
      "$HOME/.openclaw/openclaw.json"
      "$HOME/.openclaw/config.json"
      "$HOME/Library/Application Support/openclaw/openclaw.json"
    )
  else
    search_paths=(
      "$HOME/.config/openclaw/openclaw.json"
      "$HOME/.config/openclaw/config.json"
      "$HOME/.openclaw/openclaw.json"
      "$HOME/.openclaw/config.json"
      "/etc/openclaw/openclaw.json"
    )
  fi

  for p in "${search_paths[@]}"; do
    if [[ -f "$p" ]]; then
      echo "$p"
      return 0
    fi
  done

  return 1
}

get_openclaw_version() {
  if has_cmd openclaw; then
    openclaw --version 2>/dev/null || echo "unknown"
  else
    echo "not-installed"
  fi
}

get_config_value() {
  # Usage: get_config_value <config_file> <jq_filter>
  local config_file="$1"
  local filter="$2"

  if ! has_cmd jq; then
    log_error "jq is required but not installed"
    return 1
  fi

  jq -r "$filter // empty" "$config_file" 2>/dev/null
}

# ─── Finding emitter ────────────────────────────────────────────────────────
# Each scanner outputs findings as JSON objects, one per line, collected
# into a JSON array by the orchestrator.
#
# Schema:
# {
#   "id":          "CHK-XXX-NNN",      (unique check id)
#   "severity":    "critical|warn|info|ok",
#   "title":       "Short title",
#   "description": "Longer explanation",
#   "evidence":    "Relevant snippet or value",
#   "remediation": "How to fix",
#   "auto_fix":    "Optional shell command to fix"
# }

emit_finding() {
  local id="$1"
  local severity="$2"
  local title="$3"
  local description="${4:-}"
  local evidence="${5:-}"
  local remediation="${6:-}"
  local auto_fix="${7:-}"

  if has_cmd jq; then
    jq -n -c \
      --arg id "$id" \
      --arg severity "$severity" \
      --arg title "$title" \
      --arg description "$description" \
      --arg evidence "$evidence" \
      --arg remediation "$remediation" \
      --arg auto_fix "$auto_fix" \
      '{id:$id, severity:$severity, title:$title, description:$description, evidence:$evidence, remediation:$remediation, auto_fix:$auto_fix}'
  else
    # Fallback without jq: manual JSON escaping for common chars
    _json_escape() {
      local s="$1"
      s="${s//\\/\\\\}"
      s="${s//\"/\\\"}"
      s="${s//$'\n'/\\n}"
      s="${s//$'\t'/\\t}"
      printf '%s' "$s"
    }
    printf '{"id":"%s","severity":"%s","title":"%s","description":"%s","evidence":"%s","remediation":"%s","auto_fix":"%s"}\n' \
      "$(_json_escape "$id")" \
      "$(_json_escape "$severity")" \
      "$(_json_escape "$title")" \
      "$(_json_escape "$description")" \
      "$(_json_escape "$evidence")" \
      "$(_json_escape "$remediation")" \
      "$(_json_escape "$auto_fix")"
  fi
}

# ─── Globals set by the orchestrator via env vars ───────────────────────────

CLAWPINCH_DEEP="${CLAWPINCH_DEEP:-0}"
CLAWPINCH_CONFIG_DIR="${CLAWPINCH_CONFIG_DIR:-}"
CLAWPINCH_OS="${CLAWPINCH_OS:-$(detect_os)}"
