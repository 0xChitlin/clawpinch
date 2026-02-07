#!/usr/bin/env bash
set -euo pipefail

###############################################################################
# scan_git_history.sh - Git History Security Scanner
#
# Scans git repository history for accidentally committed secrets, credentials,
# and sensitive information. Outputs a JSON array of findings to stdout.
#
# Usage:
#   ./scan_git_history.sh                     # scan current directory
#   GIT_REPO_PATH=/path/to/repo ./scan_git_history.sh
###############################################################################

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Source shared helpers if available; define fallbacks otherwise
if [[ -f "${SCRIPT_DIR}/helpers/common.sh" ]]; then
    # shellcheck source=helpers/common.sh
    source "${SCRIPT_DIR}/helpers/common.sh"
fi

# Fallback: define emit_finding if not already provided by common.sh
if ! declare -f emit_finding >/dev/null 2>&1; then
    emit_finding() {
        local id="$1" severity="$2" title="$3" description="$4" evidence="$5" remediation="$6" auto_fix="${7:-}"
        jq -n \
            --arg id "$id" \
            --arg severity "$severity" \
            --arg title "$title" \
            --arg description "$description" \
            --arg evidence "$evidence" \
            --arg remediation "$remediation" \
            --arg auto_fix "$auto_fix" \
            '{id:$id, severity:$severity, title:$title, description:$description, evidence:$evidence, remediation:$remediation, auto_fix:$auto_fix}'
    }
fi

# ---------------------------------------------------------------------------
# Resolve git repository path
# ---------------------------------------------------------------------------
REPO_PATH="${GIT_REPO_PATH:-.}"

if [[ ! -d "$REPO_PATH/.git" ]]; then
    echo '[{"id":"CHK-GIT-000","severity":"info","title":"Not a git repository","description":"Could not locate .git directory","evidence":"'"$REPO_PATH"'","remediation":"Run this scanner from within a git repository","auto_fix":""}]'
    exit 0
fi

# Verify git command is available
if ! command -v git &>/dev/null; then
    echo '[{"id":"CHK-GIT-000","severity":"warn","title":"git command not found","description":"The git command is not available in PATH","evidence":"git not found","remediation":"Install git to enable history scanning","auto_fix":""}]'
    exit 0
fi

# ---------------------------------------------------------------------------
# Collect findings into an array
# ---------------------------------------------------------------------------
FINDINGS=()

# ---------------------------------------------------------------------------
# Helper: Redact secret value (show only last 4 chars)
# ---------------------------------------------------------------------------
redact_secret() {
    local value="$1"
    local len=${#value}
    if [[ $len -le 4 ]]; then
        echo "****"
    else
        echo "****${value: -4}"
    fi
}

# ---------------------------------------------------------------------------
# Secret pattern definitions (adapted from scan_secrets.py)
# Each entry is "type|pattern" separated by pipe
# ---------------------------------------------------------------------------
SECRET_PATTERNS=(
    "Slack bot token|xoxb-[A-Za-z0-9-]+"
    "Slack app token|xapp-[A-Za-z0-9-]+"
    "Slack user token|xoxp-[A-Za-z0-9-]+"
    "JWT token|eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+"
    "Discord bot token|[MN][A-Za-z0-9]{23,}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27,}"
    "Telegram bot token|[0-9]{8,10}:[A-Za-z0-9_-]{35}"
    "OpenAI API key|sk-proj-[A-Za-z0-9]{20,}"
    "OpenAI legacy key|sk-[A-Za-z0-9]{20,}"
    "Ethereum private key|0x[a-fA-F0-9]{64}"
    "Private key|-----BEGIN[[:space:]]+(RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"
    "Generic Bearer token|[Bb]earer[[:space:]]+[A-Za-z0-9_.~+/-]+=*"
    "AWS Access Key|AKIA[0-9A-Z]{16}"
    "GitHub Token|ghp_[A-Za-z0-9]{36}"
    "Generic API key|api[_-]?key[[:space:]]*[:=][[:space:]]*[\"'][A-Za-z0-9_-]{20,}[\"']"
)

# ---------------------------------------------------------------------------
# Scan git history for secrets
# ---------------------------------------------------------------------------
scan_git_history() {
    # Determine scan depth based on CLAWPINCH_DEEP
    local max_commits=100
    local time_limit=""

    if [[ "${CLAWPINCH_DEEP:-0}" == "1" ]]; then
        max_commits=1000
        time_limit="--since=6 months ago"
    fi

    # Get git log with patches
    # Format: commit hash, file path, diff lines
    # Note: --no-textconv disables textconv filters, -a treats all files as text
    local git_output
    git_output=$(cd "$REPO_PATH" && git log -p --all --no-textconv -n "$max_commits" $time_limit --format="COMMIT:%H" 2>/dev/null || true)

    if [[ -z "$git_output" ]]; then
        # Empty history or no commits
        return 0
    fi

    local current_commit=""
    local current_file=""

    # Process git log output line by line
    while IFS= read -r line; do
        # Extract commit hash
        if [[ "$line" =~ ^COMMIT:([a-f0-9]{40}) ]]; then
            current_commit="${BASH_REMATCH[1]}"
            current_file=""
            continue
        fi

        # Extract file path from diff header
        if [[ "$line" =~ ^\+\+\+[[:space:]]b/(.+)$ ]]; then
            current_file="${BASH_REMATCH[1]}"
            continue
        fi

        # Only check added lines (starting with +)
        if [[ ! "$line" =~ ^\+[^+] ]]; then
            continue
        fi

        # Skip if we don't have commit/file context
        if [[ -z "$current_commit" ]]; then
            continue
        fi

        # Remove the leading + from the diff line
        local content="${line:1}"

        # Check each secret pattern
        for pattern_entry in "${SECRET_PATTERNS[@]}"; do
            # Parse "type|pattern" format
            local secret_type="${pattern_entry%%|*}"
            local pattern="${pattern_entry#*|}"

            # Use grep -oE to extract matching secrets
            local matches
            matches=$(echo "$content" | grep -oE "$pattern" 2>/dev/null || true)

            if [[ -n "$matches" ]]; then
                while IFS= read -r secret_value; do
                    # Skip empty matches
                    [[ -z "$secret_value" ]] && continue

                    # Skip environment variable references (${VAR} or $VAR)
                    if [[ "$secret_value" =~ ^\$\{.*\}$ ]] || [[ "$secret_value" =~ ^\$[A-Z_][A-Z0-9_]*$ ]]; then
                        continue
                    fi

                    local redacted_value
                    redacted_value=$(redact_secret "$secret_value")

                    local evidence="commit=${current_commit:0:8}"
                    if [[ -n "$current_file" ]]; then
                        evidence="$evidence file=$current_file"
                    fi
                    evidence="$evidence secret_type=\"$secret_type\" value=$redacted_value"

                    local title="$secret_type found in git history"
                    local description="A $secret_type was detected in commit $current_commit"
                    if [[ -n "$current_file" ]]; then
                        description="$description in file $current_file"
                    fi
                    description="$description. This secret exists in the repository history even if it was later removed from current files."

                    local remediation="Remove secret from git history using git filter-repo or BFG Repo-Cleaner. Rotate the exposed credential immediately. See: https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/removing-sensitive-data-from-a-repository"

                    # Emit finding
                    local finding
                    finding=$(emit_finding \
                        "CHK-SEC-008" \
                        "critical" \
                        "$title" \
                        "$description" \
                        "$evidence" \
                        "$remediation" \
                        "")

                    FINDINGS+=("$finding")
                done <<< "$matches"
            fi
        done
    done <<< "$git_output"
}

# Run the scan
scan_git_history

# ---------------------------------------------------------------------------
# Output all findings as a JSON array
# ---------------------------------------------------------------------------
if [[ ${#FINDINGS[@]} -eq 0 ]]; then
    echo '[]'
else
    printf '%s\n' "${FINDINGS[@]}" | jq -s '.'
fi
