#!/usr/bin/env bash
set -euo pipefail

# ─── ClawPinch report rendering ─────────────────────────────────────────────
# Terminal UI: banner, findings, summary table.

# ─── ANSI colors ─────────────────────────────────────────────────────────────

_R='\033[0;31m'    # red      (critical)
_Y='\033[0;33m'    # yellow   (warn)
_B='\033[0;34m'    # blue     (info)
_G='\033[0;32m'    # green    (ok)
_W='\033[1;37m'    # white bold
_D='\033[2m'       # dim
_U='\033[4m'       # underline
_RST='\033[0m'     # reset

# ─── Banner ──────────────────────────────────────────────────────────────────

print_header() {
  printf '\n'
  printf "${_R}   ___  _                ___  _             _     ${_RST}\n"
  printf "${_R}  / __|| | __ _ __ __ __| _ \\(_) _ __   ___| |_   ${_RST}\n"
  printf "${_Y} | (__ | |/ _\` |\\ V  V /|  _/| || '  \\ / _|| ' \\  ${_RST}\n"
  printf "${_Y}  \\___||_|\\__,_| \\_/\\_/ |_|  |_||_|_|_|\\__||_||_| ${_RST}\n"
  printf "${_D}  OpenClaw Security Audit Toolkit   v1.0.0${_RST}\n"
  printf '\n'
}

# ─── Severity badge ─────────────────────────────────────────────────────────

_badge() {
  case "$1" in
    critical) printf "${_R}[CRITICAL]${_RST}" ;;
    warn)     printf "${_Y}[WARNING] ${_RST}" ;;
    info)     printf "${_B}[INFO]    ${_RST}" ;;
    ok)       printf "${_G}[OK]      ${_RST}" ;;
    *)        printf "[%-8s]" "$1" ;;
  esac
}

# ─── Print a single finding ─────────────────────────────────────────────────

print_finding() {
  # Expects a JSON object on stdin or as $1
  local json="${1:-$(cat)}"

  local id severity title description evidence remediation auto_fix
  id="$(echo "$json"          | jq -r '.id // ""')"
  severity="$(echo "$json"    | jq -r '.severity // "info"')"
  title="$(echo "$json"       | jq -r '.title // ""')"
  description="$(echo "$json" | jq -r '.description // ""')"
  evidence="$(echo "$json"    | jq -r '.evidence // ""')"
  remediation="$(echo "$json" | jq -r '.remediation // ""')"
  auto_fix="$(echo "$json"    | jq -r '.auto_fix // ""')"

  printf '  '
  _badge "$severity"
  printf "  ${_W}%s${_RST}" "$title"
  if [[ -n "$id" ]]; then
    printf "  ${_D}(%s)${_RST}" "$id"
  fi
  printf '\n'

  if [[ -n "$description" ]]; then
    printf "             %s\n" "$description"
  fi
  if [[ -n "$evidence" ]]; then
    printf "             ${_D}Evidence: %s${_RST}\n" "$evidence"
  fi
  if [[ -n "$remediation" ]]; then
    printf "             ${_U}Fix:${_RST} %s\n" "$remediation"
  fi
  if [[ -n "$auto_fix" ]] && [[ "${CLAWPINCH_SHOW_FIX:-0}" == "1" ]]; then
    printf "             ${_G}Auto-fix:${_RST} ${_D}%s${_RST}\n" "$auto_fix"
  fi
  printf '\n'
}

# ─── Summary counts ─────────────────────────────────────────────────────────

print_summary() {
  local critical="${1:-0}"
  local warn="${2:-0}"
  local info="${3:-0}"
  local ok="${4:-0}"

  printf "${_D}──────────────────────────────────────────────────────${_RST}\n"
  printf "  "
  if (( critical > 0 )); then
    printf "${_R}%d critical${_RST}" "$critical"
  else
    printf "${_D}0 critical${_RST}"
  fi
  printf " ${_D}\u00b7${_RST} "
  if (( warn > 0 )); then
    printf "${_Y}%d warn${_RST}" "$warn"
  else
    printf "${_D}0 warn${_RST}"
  fi
  printf " ${_D}\u00b7${_RST} "
  if (( info > 0 )); then
    printf "${_B}%d info${_RST}" "$info"
  else
    printf "${_D}0 info${_RST}"
  fi
  printf " ${_D}\u00b7${_RST} "
  if (( ok > 0 )); then
    printf "${_G}%d ok${_RST}" "$ok"
  else
    printf "${_D}0 ok${_RST}"
  fi
  printf '\n'
  printf "${_D}──────────────────────────────────────────────────────${_RST}\n"
}

# ─── Aligned table ───────────────────────────────────────────────────────────
# Usage: print_table "Header1|Header2|Header3" "val1|val2|val3" "val4|val5|val6"
# Uses | as delimiter.

print_table() {
  local header="$1"
  shift
  local rows=("$@")

  # Compute column widths
  local IFS='|'
  local -a hcols
  read -ra hcols <<< "$header"
  local ncols=${#hcols[@]}
  local -a widths=()
  for (( i=0; i<ncols; i++ )); do
    widths+=( ${#hcols[$i]} )
  done

  for row in "${rows[@]}"; do
    local -a rcols
    read -ra rcols <<< "$row"
    for (( i=0; i<ncols; i++ )); do
      local len=${#rcols[$i]:-0}
      if (( len > widths[i] )); then
        widths[$i]=$len
      fi
    done
  done

  # Print header
  printf '  '
  for (( i=0; i<ncols; i++ )); do
    printf "${_W}%-*s${_RST}  " "${widths[$i]}" "${hcols[$i]}"
  done
  printf '\n  '
  for (( i=0; i<ncols; i++ )); do
    printf '%*s  ' "${widths[$i]}" '' | tr ' ' '─'
  done
  printf '\n'

  # Print rows
  for row in "${rows[@]}"; do
    local -a rcols
    read -ra rcols <<< "$row"
    printf '  '
    for (( i=0; i<ncols; i++ )); do
      printf "%-*s  " "${widths[$i]}" "${rcols[$i]:-}"
    done
    printf '\n'
  done
  printf '\n'
}

# ─── Progress indicator ─────────────────────────────────────────────────────

print_progress() {
  local current="$1"
  local total="$2"
  local label="${3:-Scanning}"

  local pct=0
  if (( total > 0 )); then
    pct=$(( current * 100 / total ))
  fi

  local bar_width=30
  local filled=$(( pct * bar_width / 100 ))
  local empty=$(( bar_width - filled ))

  printf "\r  ${_D}%s${_RST} [" "$label"
  printf "${_G}%0.s#${_RST}" $(seq 1 "$filled" 2>/dev/null) || true
  printf '%0.s-' $(seq 1 "$empty" 2>/dev/null) || true
  printf '] %3d%% (%d/%d)' "$pct" "$current" "$total"

  if (( current == total )); then
    printf '\n'
  fi
}
