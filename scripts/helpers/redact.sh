#!/usr/bin/env bash
set -euo pipefail

# ─── ClawPinch secret redaction helpers ──────────────────────────────────────
# Mask sensitive values before printing or logging.

# Sensitive key patterns (case-insensitive matching done in functions)
_SENSITIVE_KEYS='(token|password|passwd|secret|apikey|api_key|api-key|auth|credential|private.?key|access.?key|signing.?key|encryption.?key|client.?secret|bearer)'

# ─── Redact a single value ───────────────────────────────────────────────────
# Shows only the last 4 characters, replacing the rest with asterisks.
# Short values (<=4 chars) are fully masked.

redact_value() {
  local val="$1"
  local len=${#val}

  if (( len <= 4 )); then
    printf '%*s' "$len" '' | tr ' ' '*'
  else
    local masked_len=$(( len - 4 ))
    printf '%*s' "$masked_len" '' | tr ' ' '*'
    printf '%s' "${val: -4}"
  fi
}

# ─── Redact sensitive fields in a JSON string ────────────────────────────────
# Scans for keys matching sensitive patterns and replaces their values.
# Requires jq.

redact_json_secrets() {
  local json="${1:-$(cat)}"

  if ! command -v jq &>/dev/null; then
    # Fallback: regex-based redaction for common patterns
    echo "$json" | sed -E \
      -e "s/(\"(token|password|passwd|secret|apikey|api_key|api-key|auth|credential|private_key|access_key|signing_key|encryption_key|client_secret|bearer)\"[[:space:]]*:[[:space:]]*\")[^\"]{0,4}\"/\1****\"/gi" \
      -e "s/(\"(token|password|passwd|secret|apikey|api_key|api-key|auth|credential|private_key|access_key|signing_key|encryption_key|client_secret|bearer)\"[[:space:]]*:[[:space:]]*\")[^\"]*(....)\"/\1****\3\"/gi"
    return
  fi

  echo "$json" | jq -c '
    def redact_val:
      if type == "string" then
        if (. | length) <= 4 then
          (. | length) as $n | ("*" * $n)
        else
          ((. | length) - 4) as $n | ("*" * $n) + (.[-4:])
        end
      else .
      end;

    walk(
      if type == "object" then
        to_entries | map(
          if (.key | test("(?i)(token|password|passwd|secret|apikey|api_key|api-key|auth|credential|private.?key|access.?key|signing.?key|encryption.?key|client.?secret|bearer)")) then
            .value = (.value | redact_val)
          else .
          end
        ) | from_entries
      else .
      end
    )
  ' 2>/dev/null || echo "$json"
}

# ─── Redact sensitive-looking values in a plain text line ────────────────────
# Matches patterns like KEY=VALUE or key: value and masks the value portion.

redact_line() {
  local line="$1"

  # Pattern: KEY=VALUE (env-file style)
  line="$(echo "$line" | sed -E \
    "s/(^|[[:space:]])(${_SENSITIVE_KEYS})[[:space:]]*=[[:space:]]*([^[:space:]]+)/\1\2=****\5/gi" 2>/dev/null || echo "$line")"

  # Pattern: "key": "value" (JSON-ish inline)
  line="$(echo "$line" | sed -E \
    "s/(\"${_SENSITIVE_KEYS}\"[[:space:]]*:[[:space:]]*\")[^\"]+\"/\1****\"/gi" 2>/dev/null || echo "$line")"

  echo "$line"
}

# ─── Redact a whole file's content ───────────────────────────────────────────

redact_file_content() {
  local file="$1"
  while IFS= read -r line; do
    redact_line "$line"
  done < "$file"
}
