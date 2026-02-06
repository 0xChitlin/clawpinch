#!/usr/bin/env bash
set -euo pipefail

# ─── ClawPinch: Cron Job Security Scanner ────────────────────────────────────
# Audits OpenClaw scheduled/cron jobs for security issues.
# Reads from ~/.openclaw/cron/jobs.json
#
# Checks:
#   CHK-CRN-001  Hardcoded API keys/tokens in payload
#   CHK-CRN-002  Bearer tokens in payload
#   CHK-CRN-003  External API calls with embedded credentials
#   CHK-CRN-004  Weak/cheap models susceptible to prompt injection
#   CHK-CRN-005  Disabled jobs still containing sensitive data
#   CHK-CRN-006  Shared session context (sessionTarget="main")
#   CHK-CRN-007  No timeout configured
#   CHK-CRN-008  Unusually high frequency (< 5 min)

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

if [[ -f "$SCRIPT_DIR/helpers/common.sh" ]]; then
  source "$SCRIPT_DIR/helpers/common.sh"
else
  # Minimal fallback if common.sh is not available
  log_info()  { printf "[info]  %s\n" "$*" >&2; }
  log_warn()  { printf "[warn]  %s\n" "$*" >&2; }
  log_error() { printf "[error] %s\n" "$*" >&2; }
  has_cmd() { command -v "$1" &>/dev/null; }
  emit_finding() {
    local id="$1" severity="$2" title="$3" description="${4:-}" evidence="${5:-}" remediation="${6:-}" auto_fix="${7:-}"
    printf '{"id":"%s","severity":"%s","title":"%s","description":"%s","evidence":"%s","remediation":"%s","auto_fix":"%s"}\n' \
      "$id" "$severity" "$title" "$description" "$evidence" "$remediation" "$auto_fix"
  }
fi

# ─── Prerequisites ───────────────────────────────────────────────────────────

require_cmd jq

CRON_FILE="${CLAWPINCH_CRON_FILE:-$HOME/.openclaw/cron/jobs.json}"

if [[ ! -f "$CRON_FILE" ]]; then
  log_info "No cron jobs file found at $CRON_FILE - skipping cron scan"
  echo "[]"
  exit 0
fi

if ! jq empty "$CRON_FILE" 2>/dev/null; then
  log_error "Invalid JSON in $CRON_FILE"
  echo "[]"
  exit 1
fi

FINDINGS=()

JOB_COUNT=$(jq '.jobs | length' "$CRON_FILE")
log_info "Scanning $JOB_COUNT cron job(s) from $CRON_FILE"

# ─── Secret patterns ────────────────────────────────────────────────────────
# Regex patterns for detecting hardcoded secrets in payloads
API_KEY_PATTERNS=(
  'sk-[a-zA-Z0-9]{20,}'
  'sk-proj-[a-zA-Z0-9_-]{20,}'
  'sk-ant-[a-zA-Z0-9_-]{20,}'
  'AKIA[0-9A-Z]{16}'
  'api[_-]?key["\s:=]+[a-zA-Z0-9_-]{16,}'
  'api[_-]?secret["\s:=]+[a-zA-Z0-9_-]{16,}'
  'token["\s:=]+[a-zA-Z0-9_-]{20,}'
  'xox[bpras]-[0-9a-zA-Z-]+'
  'ghp_[a-zA-Z0-9]{36}'
  'gho_[a-zA-Z0-9]{36}'
  'glpat-[a-zA-Z0-9_-]{20,}'
  'eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}'
)

# Weak/cheap models susceptible to prompt injection
WEAK_MODELS=(
  "kimi-k2.5-free"
  "gpt-3.5"
  "gpt-3.5-turbo"
  "text-davinci"
  "text-babbage"
  "text-curie"
  "text-ada"
  "llama-2-7b"
  "llama-2-13b"
  "llama-3-8b"
  "mistral-7b"
  "phi-2"
  "phi-3-mini"
  "gemma-2b"
  "gemma-7b"
  "tinyllama"
)

# ─── Helpers ─────────────────────────────────────────────────────────────────

# Safely extract text payload from a job (handles both .text and .message)
get_payload_text() {
  local idx="$1"
  local text
  text=$(jq -r ".jobs[$idx].payload.text // .jobs[$idx].payload.message // \"\"" "$CRON_FILE")
  echo "$text"
}

# Get full payload as string for scanning
get_payload_full() {
  local idx="$1"
  jq -c ".jobs[$idx].payload" "$CRON_FILE"
}

# Redact sensitive values in evidence strings
redact_evidence() {
  local text="$1"
  # Truncate long evidence and mask potential secrets
  text="${text:0:200}"
  # Mask anything that looks like a key/token value
  text=$(echo "$text" | sed -E 's/(Bearer |Authorization: )[a-zA-Z0-9_-]{8}[a-zA-Z0-9_-]*/\1[REDACTED]/g')
  text=$(echo "$text" | sed -E 's/(sk-[a-zA-Z0-9_-]{4})[a-zA-Z0-9_-]*/\1...[REDACTED]/g')
  text=$(echo "$text" | sed -E 's/(AKIA[0-9A-Z]{4})[0-9A-Z]*/\1...[REDACTED]/g')
  text=$(echo "$text" | sed -E 's/(api[_-]?key[^a-zA-Z0-9]*)[a-zA-Z0-9_-]{8}[a-zA-Z0-9_-]*/\1[REDACTED]/g')
  # Escape for JSON embedding
  text="${text//\\/\\\\}"
  text="${text//\"/\\\"}"
  text="${text//$'\n'/\\n}"
  text="${text//$'\t'/\\t}"
  echo "$text"
}

# ─── Scan each job ───────────────────────────────────────────────────────────

for (( i=0; i<JOB_COUNT; i++ )); do
  JOB_ID=$(jq -r ".jobs[$i].id" "$CRON_FILE")
  JOB_NAME=$(jq -r ".jobs[$i].name" "$CRON_FILE")
  JOB_ENABLED=$(jq -r ".jobs[$i].enabled" "$CRON_FILE")
  SESSION_TARGET=$(jq -r ".jobs[$i].sessionTarget // \"\"" "$CRON_FILE")
  TIMEOUT=$(jq -r ".jobs[$i].payload.timeoutSeconds // \"\"" "$CRON_FILE")
  MODEL=$(jq -r ".jobs[$i].payload.model // \"\"" "$CRON_FILE")
  SCHEDULE_KIND=$(jq -r ".jobs[$i].schedule.kind // \"\"" "$CRON_FILE")
  EVERY_MS=$(jq -r ".jobs[$i].schedule.everyMs // 0" "$CRON_FILE")

  PAYLOAD_TEXT=$(get_payload_text "$i")
  PAYLOAD_FULL=$(get_payload_full "$i")

  SAFE_NAME="${JOB_NAME//\"/\\\"}"

  log_info "Checking job: $JOB_NAME ($JOB_ID)"

  # ── CHK-CRN-001: Hardcoded API keys/tokens ──────────────────────────────
  for pattern in "${API_KEY_PATTERNS[@]}"; do
    if echo "$PAYLOAD_TEXT" | grep -qEi "$pattern"; then
      matched=$(echo "$PAYLOAD_TEXT" | grep -oEi "$pattern" | head -1)
      evidence=$(redact_evidence "Found in job '$SAFE_NAME': $matched")
      FINDINGS+=("$(emit_finding \
        "CHK-CRN-001" \
        "critical" \
        "Hardcoded API key/token in cron job payload" \
        "Job '$SAFE_NAME' ($JOB_ID) contains what appears to be a hardcoded API key or token in its payload. Cron payloads are stored in plaintext and may be logged." \
        "$evidence" \
        "Remove hardcoded credentials from cron payloads. Use environment variables or a secrets manager instead.")")
      break
    fi
  done

  # ── CHK-CRN-002: Bearer tokens ──────────────────────────────────────────
  if echo "$PAYLOAD_TEXT" | grep -qEi 'Bearer\s+[a-zA-Z0-9_-]{8,}'; then
    matched=$(echo "$PAYLOAD_TEXT" | grep -oEi 'Bearer\s+[a-zA-Z0-9_-]{8,}' | head -1)
    evidence=$(redact_evidence "Found in job '$SAFE_NAME': $matched")
    FINDINGS+=("$(emit_finding \
      "CHK-CRN-002" \
      "critical" \
      "Bearer token in cron job payload" \
      "Job '$SAFE_NAME' ($JOB_ID) contains a Bearer token in its payload text. Even revoked tokens indicate a pattern of embedding credentials in scheduled tasks." \
      "$evidence" \
      "Never embed Bearer tokens directly in cron payloads. Use a credential store or environment variable reference.")")
  fi

  # ── CHK-CRN-003: External API calls with credentials ────────────────────
  if echo "$PAYLOAD_TEXT" | grep -qEi 'curl.*(-H|--header).*Authorization'; then
    evidence=$(redact_evidence "Job '$SAFE_NAME' makes authenticated external API calls via curl")
    FINDINGS+=("$(emit_finding \
      "CHK-CRN-003" \
      "warn" \
      "External API call with credentials in cron job" \
      "Job '$SAFE_NAME' ($JOB_ID) contains curl commands with Authorization headers. Credentials in scheduled tasks are at risk of exposure through logs and process listings." \
      "$evidence" \
      "Move API calls with credentials into a dedicated script that reads secrets from a secure store at runtime.")")
  elif echo "$PAYLOAD_TEXT" | grep -qEi '(https?://[^ ]*[?&](api_key|token|key|secret|auth)=)'; then
    evidence=$(redact_evidence "Job '$SAFE_NAME' passes credentials as URL parameters")
    FINDINGS+=("$(emit_finding \
      "CHK-CRN-003" \
      "warn" \
      "Credentials in URL parameters in cron job" \
      "Job '$SAFE_NAME' ($JOB_ID) passes credentials as URL query parameters, which may be logged in server access logs and browser history." \
      "$evidence" \
      "Move credentials from URL parameters to secure headers or a credential store.")")
  fi

  # ── CHK-CRN-004: Weak models susceptible to prompt injection ─────────────
  if [[ -n "$MODEL" ]]; then
    for weak_model in "${WEAK_MODELS[@]}"; do
      if echo "$MODEL" | grep -qi "$weak_model"; then
        FINDINGS+=("$(emit_finding \
          "CHK-CRN-004" \
          "warn" \
          "Cron job uses weak model susceptible to prompt injection" \
          "Job '$SAFE_NAME' ($JOB_ID) uses model '$MODEL' which is a smaller/free model with weaker instruction following. Automated cron jobs using weak models are more susceptible to prompt injection when processing untrusted content." \
          "model=$MODEL in job '$SAFE_NAME'" \
          "Use a more capable model for automated tasks that interact with untrusted content, or add input validation and output filtering.")")
        break
      fi
    done
  fi

  # ── CHK-CRN-005: Disabled jobs still containing sensitive data ───────────
  if [[ "$JOB_ENABLED" == "false" ]]; then
    has_sensitive=false
    for pattern in "${API_KEY_PATTERNS[@]}"; do
      if echo "$PAYLOAD_TEXT" | grep -qEi "$pattern"; then
        has_sensitive=true
        break
      fi
    done
    if echo "$PAYLOAD_TEXT" | grep -qEi 'Bearer\s+[a-zA-Z0-9_-]{8,}'; then
      has_sensitive=true
    fi
    if echo "$PAYLOAD_TEXT" | grep -qEi 'Authorization'; then
      has_sensitive=true
    fi

    if [[ "$has_sensitive" == "true" ]]; then
      FINDINGS+=("$(emit_finding \
        "CHK-CRN-005" \
        "info" \
        "Disabled cron job still contains sensitive data" \
        "Job '$SAFE_NAME' ($JOB_ID) is disabled but its payload still contains credentials or sensitive data. Disabled jobs are still stored in plaintext and may be restored by mistake." \
        "Disabled job '$SAFE_NAME' contains credentials in payload" \
        "Remove or rotate credentials in disabled cron jobs. Delete the job entirely if it is no longer needed.")")
    fi
  fi

  # ── CHK-CRN-006: Shared session context ─────────────────────────────────
  if [[ "$SESSION_TARGET" == "main" ]]; then
    FINDINGS+=("$(emit_finding \
      "CHK-CRN-006" \
      "warn" \
      "Cron job shares main session context" \
      "Job '$SAFE_NAME' ($JOB_ID) runs with sessionTarget='main', meaning it shares the agent's primary conversation context. A compromised or misbehaving cron job could read or corrupt the main session state." \
      "sessionTarget=main in job '$SAFE_NAME'" \
      "Set sessionTarget to 'isolated' to run cron jobs in a sandboxed session that cannot access the main conversation context.")")
  fi

  # ── CHK-CRN-007: No timeout configured ──────────────────────────────────
  if [[ -z "$TIMEOUT" ]] || [[ "$TIMEOUT" == "null" ]]; then
    FINDINGS+=("$(emit_finding \
      "CHK-CRN-007" \
      "warn" \
      "Cron job has no timeout configured" \
      "Job '$SAFE_NAME' ($JOB_ID) does not set a timeoutSeconds value. Without a timeout, a stuck or malicious job could run indefinitely, consuming resources or accumulating API costs." \
      "No timeoutSeconds in job '$SAFE_NAME'" \
      "Add a timeoutSeconds field to the cron job payload to limit execution time.")")
  fi

  # ── CHK-CRN-008: Unusually high frequency ───────────────────────────────
  if [[ "$SCHEDULE_KIND" == "every" ]] && [[ "$EVERY_MS" -gt 0 ]] && [[ "$EVERY_MS" -lt 300000 ]]; then
    freq_sec=$((EVERY_MS / 1000))
    FINDINGS+=("$(emit_finding \
      "CHK-CRN-008" \
      "info" \
      "Cron job frequency is unusually high" \
      "Job '$SAFE_NAME' ($JOB_ID) runs every ${freq_sec}s (< 5 minutes). High-frequency automated jobs increase API costs and the attack surface for prompt injection if processing external content." \
      "everyMs=$EVERY_MS (${freq_sec}s) in job '$SAFE_NAME'" \
      "Review whether this frequency is necessary. Consider increasing the interval or batching operations.")")
  fi

done

# ─── Output results ──────────────────────────────────────────────────────────

FINDING_COUNT=${#FINDINGS[@]}
log_info "Cron scan complete: $FINDING_COUNT finding(s)"

if [[ "$FINDING_COUNT" -eq 0 ]]; then
  echo "[]"
else
  # Build JSON array from individual findings
  printf '%s\n' "${FINDINGS[@]}" | jq -s '.'
fi
