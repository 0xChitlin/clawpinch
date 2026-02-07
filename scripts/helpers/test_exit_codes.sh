#!/usr/bin/env bash
set -euo pipefail

# ─── ClawPinch Exit Code Integration Test ─────────────────────────────────────
# Tests all exit code scenarios (0, 1, 2, 3) with different flags and findings.
# This test creates mock scanners with specific findings and verifies that
# clawpinch.sh exits with the correct code for each scenario.

# Colors
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly RESET='\033[0m'

# Test counters
TESTS_RUN=0
TESTS_PASSED=0
TESTS_FAILED=0

# Test output directory
TEST_DIR=""

# List of mock scanners created (for cleanup)
declare -a MOCK_SCANNERS=()

# List of hidden real scanners (for restoration)
declare -a HIDDEN_SCANNERS=()

# ─── Helpers ──────────────────────────────────────────────────────────────────

log_info() {
  printf "${BLUE}ℹ${RESET} %s\n" "$1"
}

log_success() {
  printf "${GREEN}✓${RESET} %s\n" "$1"
}

log_error() {
  printf "${RED}✗${RESET} %s\n" "$1"
}

log_warning() {
  printf "${YELLOW}⚠${RESET} %s\n" "$1"
}

assert_pass() {
  local test_name="$1"
  TESTS_RUN=$((TESTS_RUN + 1))
  TESTS_PASSED=$((TESTS_PASSED + 1))
  log_success "TEST $TESTS_RUN: $test_name"
}

assert_fail() {
  local test_name="$1"
  local reason="$2"
  TESTS_RUN=$((TESTS_RUN + 1))
  TESTS_FAILED=$((TESTS_FAILED + 1))
  log_error "TEST $TESTS_RUN: $test_name"
  log_error "  Reason: $reason"
}

# ─── Test Setup ───────────────────────────────────────────────────────────────

setup_test_environment() {
  log_info "Setting up test environment..."

  # Create temporary test directory
  TEST_DIR="$(mktemp -d)"
  export CLAWPINCH_TEST_DIR="$TEST_DIR"

  # Hide real scanners so only our test scanners run
  hide_real_scanners

  log_success "Test environment created at $TEST_DIR"
}

cleanup_test_environment() {
  # Clean up mock scanners first
  cleanup_mock_scanners

  # Restore real scanners
  restore_real_scanners

  # Clean up test directory
  if [[ -n "$TEST_DIR" ]] && [[ -d "$TEST_DIR" ]]; then
    rm -rf "$TEST_DIR"
    log_info "Test environment cleaned up"
  fi
}

# ─── Mock Scanner Helpers ─────────────────────────────────────────────────────

# Hide real scanners by renaming them temporarily
hide_real_scanners() {
  # Find all real scanner scripts and hide them
  for scanner in ./scripts/scan_*.sh ./scripts/scan_*.py; do
    if [[ -f "$scanner" ]] && [[ ! "$scanner" =~ scan_test_ ]]; then
      local hidden="${scanner}.hidden"
      mv "$scanner" "$hidden" 2>/dev/null || true
      HIDDEN_SCANNERS+=("$hidden")
    fi
  done
}

# Restore hidden real scanners
restore_real_scanners() {
  if [[ ${#HIDDEN_SCANNERS[@]} -gt 0 ]]; then
    for scanner in "${HIDDEN_SCANNERS[@]}"; do
      if [[ -f "$scanner" ]]; then
        local original="${scanner%.hidden}"
        mv "$scanner" "$original" 2>/dev/null || true
      fi
    done
  fi
  HIDDEN_SCANNERS=()
}

# Prepare for a new test by cleaning up previous mock scanners
prepare_test() {
  cleanup_mock_scanners
}

# Create a mock scanner in the scripts directory that outputs specific findings
create_mock_scanner() {
  local scanner_name="$1"
  local findings_json="$2"
  local scanner_path="./scripts/scan_test_${scanner_name}.sh"

  cat > "$scanner_path" <<EOF
#!/usr/bin/env bash
cat <<'FINDINGS_EOF'
$findings_json
FINDINGS_EOF
EOF

  chmod +x "$scanner_path"
  MOCK_SCANNERS+=("$scanner_path")
  echo "$scanner_path"
}

# Create a mock scanner that fails (for exit code 3)
create_failing_scanner() {
  local scanner_name="$1"
  local scanner_path="./scripts/scan_test_${scanner_name}.sh"

  cat > "$scanner_path" <<'EOF'
#!/usr/bin/env bash
# Output invalid JSON to stdout (not stderr, since clawpinch suppresses stderr)
echo "INVALID JSON OUTPUT {{{"
exit 0
EOF

  chmod +x "$scanner_path"
  MOCK_SCANNERS+=("$scanner_path")
  echo "$scanner_path"
}

# Clean up all mock scanners
cleanup_mock_scanners() {
  if [[ ${#MOCK_SCANNERS[@]} -gt 0 ]]; then
    for scanner in "${MOCK_SCANNERS[@]}"; do
      if [[ -f "$scanner" ]]; then
        rm -f "$scanner"
      fi
    done
  fi
  MOCK_SCANNERS=()
}

# Run clawpinch and capture exit code
run_clawpinch_with_exit_code() {
  local args="$1"
  local exit_code=0

  # Run clawpinch with --no-interactive and --json to avoid interactive prompts
  bash ./clawpinch.sh --no-interactive --json $args >/dev/null 2>&1 || exit_code=$?

  echo "$exit_code"
}

# ─── Test: Exit Code 0 - Clean Scan ──────────────────────────────────────────

test_exit_code_0_clean() {
  log_info "Test 1: Exit code 0 - clean scan (no findings)"

  # Clean up any previous mock scanners
  cleanup_mock_scanners

  # Create a scanner with no findings
  create_mock_scanner "clean" "[]"

  # Run clawpinch
  local exit_code
  exit_code="$(run_clawpinch_with_exit_code "")"

  if [[ "$exit_code" -eq 0 ]]; then
    assert_pass "Exit code 0 for clean scan (no findings)"
    return 0
  else
    assert_fail "Exit code 0 clean" "Expected exit code 0, got $exit_code"
    return 1
  fi
}

# ─── Test: Exit Code 0 - Findings Below Threshold ────────────────────────────

test_exit_code_0_below_threshold() {
  log_info "Test 2: Exit code 0 - warnings with --severity-threshold=critical"

  # Prepare for test
  prepare_test

  # Create a scanner with only warnings
  create_mock_scanner "warnings" '[
    {
      "id": "CHK-CFG-001",
      "severity": "warn",
      "title": "Warning finding",
      "description": "This is a warning",
      "evidence": "test",
      "remediation": "Fix it",
      "auto_fix": ""
    }
  ]'

  # Run clawpinch with critical threshold (should ignore warnings)
  local exit_code
  exit_code="$(run_clawpinch_with_exit_code "--severity-threshold critical")"

  if [[ "$exit_code" -eq 0 ]]; then
    assert_pass "Exit code 0 when warnings exist but threshold is critical"
    return 0
  else
    assert_fail "Exit code 0 below threshold" "Expected exit code 0, got $exit_code"
    return 1
  fi
}

# ─── Test: Exit Code 1 - Critical Findings ────────────────────────────────────

test_exit_code_1_critical() {
  log_info "Test 3: Exit code 1 - critical findings present"

  # Prepare for test
  prepare_test

  # Create a scanner with critical findings
  create_mock_scanner "critical" '[
    {
      "id": "CHK-SEC-001",
      "severity": "critical",
      "title": "Critical security issue",
      "description": "Critical finding",
      "evidence": "test",
      "remediation": "Fix immediately",
      "auto_fix": ""
    }
  ]'

  # Run clawpinch
  local exit_code
  exit_code="$(run_clawpinch_with_exit_code "")"

  if [[ "$exit_code" -eq 1 ]]; then
    assert_pass "Exit code 1 when critical findings exist"
    return 0
  else
    assert_fail "Exit code 1 critical" "Expected exit code 1, got $exit_code"
    return 1
  fi
}

# ─── Test: Exit Code 2 - Warning Findings (Default) ──────────────────────────

test_exit_code_2_warnings_default() {
  log_info "Test 4: Exit code 2 - warning findings (default threshold)"

  # Prepare for test
  prepare_test

  # Create a scanner with only warnings
  create_mock_scanner "warn_default" '[
    {
      "id": "CHK-CFG-002",
      "severity": "warn",
      "title": "Warning finding",
      "description": "Warning",
      "evidence": "test",
      "remediation": "Fix it",
      "auto_fix": ""
    }
  ]'

  # Run clawpinch without threshold (default treats warn as threshold)
  local exit_code
  exit_code="$(run_clawpinch_with_exit_code "")"

  if [[ "$exit_code" -eq 2 ]]; then
    assert_pass "Exit code 2 for warnings with default threshold"
    return 0
  else
    assert_fail "Exit code 2 warnings default" "Expected exit code 2, got $exit_code"
    return 1
  fi
}

# ─── Test: Exit Code 2 - Warning Findings (Explicit) ─────────────────────────

test_exit_code_2_warnings_explicit() {
  log_info "Test 5: Exit code 2 - warning findings with --severity-threshold=warn"

  # Prepare for test
  prepare_test

  # Create a scanner with only warnings
  create_mock_scanner "warn_explicit" '[
    {
      "id": "CHK-CFG-003",
      "severity": "warn",
      "title": "Warning finding",
      "description": "Warning",
      "evidence": "test",
      "remediation": "Fix it",
      "auto_fix": ""
    }
  ]'

  # Run clawpinch with warn threshold
  local exit_code
  exit_code="$(run_clawpinch_with_exit_code "--severity-threshold warn")"

  if [[ "$exit_code" -eq 2 ]]; then
    assert_pass "Exit code 2 for warnings with --severity-threshold=warn"
    return 0
  else
    assert_fail "Exit code 2 warnings explicit" "Expected exit code 2, got $exit_code"
    return 1
  fi
}

# ─── Test: Exit Code 2 - Info Findings ───────────────────────────────────────

test_exit_code_2_info() {
  log_info "Test 6: Exit code 2 - info findings with --severity-threshold=info"

  # Prepare for test
  prepare_test

  # Create a scanner with only info findings
  create_mock_scanner "info" '[
    {
      "id": "CHK-CFG-004",
      "severity": "info",
      "title": "Info finding",
      "description": "Information",
      "evidence": "test",
      "remediation": "Note this",
      "auto_fix": ""
    }
  ]'

  # Run clawpinch with info threshold
  local exit_code
  exit_code="$(run_clawpinch_with_exit_code "--severity-threshold info")"

  if [[ "$exit_code" -eq 2 ]]; then
    assert_pass "Exit code 2 for info findings with --severity-threshold=info"
    return 0
  else
    assert_fail "Exit code 2 info" "Expected exit code 2, got $exit_code"
    return 1
  fi
}

# ─── Test: Exit Code 0 - Info Below Threshold ────────────────────────────────

test_exit_code_0_info_below_threshold() {
  log_info "Test 7: Exit code 0 - info findings with --severity-threshold=warn"

  # Prepare for test
  prepare_test

  # Create a scanner with only info findings
  create_mock_scanner "info_below" '[
    {
      "id": "CHK-CFG-005",
      "severity": "info",
      "title": "Info finding",
      "description": "Information",
      "evidence": "test",
      "remediation": "Note this",
      "auto_fix": ""
    }
  ]'

  # Run clawpinch with warn threshold (should ignore info)
  local exit_code
  exit_code="$(run_clawpinch_with_exit_code "--severity-threshold warn")"

  if [[ "$exit_code" -eq 0 ]]; then
    assert_pass "Exit code 0 for info findings below warn threshold"
    return 0
  else
    assert_fail "Exit code 0 info below threshold" "Expected exit code 0, got $exit_code"
    return 1
  fi
}

# ─── Test: Exit Code 2 - OK Findings ─────────────────────────────────────────

test_exit_code_2_ok() {
  log_info "Test 8: Exit code 2 - ok findings with --severity-threshold=ok"

  # Prepare for test
  prepare_test

  # Create a scanner with only ok findings
  create_mock_scanner "ok" '[
    {
      "id": "CHK-CFG-006",
      "severity": "ok",
      "title": "OK finding",
      "description": "All good",
      "evidence": "test",
      "remediation": "None needed",
      "auto_fix": ""
    }
  ]'

  # Run clawpinch with ok threshold
  local exit_code
  exit_code="$(run_clawpinch_with_exit_code "--severity-threshold ok")"

  if [[ "$exit_code" -eq 2 ]]; then
    assert_pass "Exit code 2 for ok findings with --severity-threshold=ok"
    return 0
  else
    assert_fail "Exit code 2 ok" "Expected exit code 2, got $exit_code"
    return 1
  fi
}

# ─── Test: Exit Code 3 - Scan Error ──────────────────────────────────────────

test_exit_code_3_scan_error() {
  log_info "Test 9: Exit code 3 - scan error (scanner fails)"

  # Prepare for test
  prepare_test

  # Create a failing scanner
  create_failing_scanner "failure"

  # Run clawpinch
  local exit_code
  exit_code="$(run_clawpinch_with_exit_code "")"

  if [[ "$exit_code" -eq 3 ]]; then
    assert_pass "Exit code 3 when scanner fails"
    return 0
  else
    assert_fail "Exit code 3 scan error" "Expected exit code 3, got $exit_code"
    return 1
  fi
}

# ─── Test: --fail-on Flag - Matching Check ID ────────────────────────────────

test_fail_on_matching() {
  log_info "Test 10: --fail-on matching check ID causes exit 1"

  # Prepare for test
  prepare_test

  # Create a scanner with info findings (normally wouldn't cause failure)
  create_mock_scanner "failon_match" '[
    {
      "id": "CHK-CFG-007",
      "severity": "info",
      "title": "Info finding",
      "description": "Information",
      "evidence": "test",
      "remediation": "Note this",
      "auto_fix": ""
    }
  ]'

  # Run clawpinch with --fail-on matching the check ID
  local exit_code
  exit_code="$(run_clawpinch_with_exit_code "--fail-on CHK-CFG-007")"

  if [[ "$exit_code" -eq 1 ]]; then
    assert_pass "--fail-on causes exit 1 when check ID matches"
    return 0
  else
    assert_fail "--fail-on matching" "Expected exit code 1, got $exit_code"
    return 1
  fi
}

# ─── Test: --fail-on Flag - Non-Matching Check ID ────────────────────────────

test_fail_on_non_matching() {
  log_info "Test 11: --fail-on non-matching check ID doesn't affect exit code"

  # Prepare for test
  prepare_test

  # Create a scanner with info findings
  create_mock_scanner "failon_nomatch" '[
    {
      "id": "CHK-CFG-008",
      "severity": "info",
      "title": "Info finding",
      "description": "Information",
      "evidence": "test",
      "remediation": "Note this",
      "auto_fix": ""
    }
  ]'

  # Run clawpinch with --fail-on non-matching check ID and critical threshold
  local exit_code
  exit_code="$(run_clawpinch_with_exit_code "--fail-on CHK-XXX-999 --severity-threshold critical")"

  if [[ "$exit_code" -eq 0 ]]; then
    assert_pass "--fail-on doesn't affect exit when check ID doesn't match"
    return 0
  else
    assert_fail "--fail-on non-matching" "Expected exit code 0, got $exit_code"
    return 1
  fi
}

# ─── Test: --fail-on Multiple Check IDs ──────────────────────────────────────

test_fail_on_multiple() {
  log_info "Test 12: --fail-on with comma-separated list"

  # Prepare for test
  prepare_test

  # Create a scanner with multiple findings
  create_mock_scanner "failon_multi" '[
    {
      "id": "CHK-CFG-009",
      "severity": "info",
      "title": "Info finding 1",
      "description": "Information",
      "evidence": "test",
      "remediation": "Note this",
      "auto_fix": ""
    },
    {
      "id": "CHK-CFG-010",
      "severity": "info",
      "title": "Info finding 2",
      "description": "Information",
      "evidence": "test",
      "remediation": "Note this",
      "auto_fix": ""
    }
  ]'

  # Run clawpinch with --fail-on matching one of the IDs
  local exit_code
  exit_code="$(run_clawpinch_with_exit_code "--fail-on CHK-CFG-009,CHK-XXX-999")"

  if [[ "$exit_code" -eq 1 ]]; then
    assert_pass "--fail-on with comma-separated list causes exit 1 when any ID matches"
    return 0
  else
    assert_fail "--fail-on multiple" "Expected exit code 1, got $exit_code"
    return 1
  fi
}

# ─── Test: Critical Always Wins ──────────────────────────────────────────────

test_critical_always_wins() {
  log_info "Test 13: Critical findings always cause exit 1 (regardless of threshold)"

  # Prepare for test
  prepare_test

  # Create a scanner with critical findings
  create_mock_scanner "critical_wins" '[
    {
      "id": "CHK-SEC-002",
      "severity": "critical",
      "title": "Critical security issue",
      "description": "Critical finding",
      "evidence": "test",
      "remediation": "Fix immediately",
      "auto_fix": ""
    }
  ]'

  # Run clawpinch with info threshold (critical should still trigger exit 1)
  local exit_code
  exit_code="$(run_clawpinch_with_exit_code "--severity-threshold info")"

  if [[ "$exit_code" -eq 1 ]]; then
    assert_pass "Critical findings always cause exit 1 regardless of threshold"
    return 0
  else
    assert_fail "Critical always wins" "Expected exit code 1, got $exit_code"
    return 1
  fi
}

# ─── Test: Mixed Findings - Critical Priority ─────────────────────────────────

test_mixed_findings_critical_priority() {
  log_info "Test 14: Mixed findings - critical takes priority over warnings"

  # Prepare for test
  prepare_test

  # Create a scanner with both critical and warning findings
  create_mock_scanner "mixed" '[
    {
      "id": "CHK-SEC-003",
      "severity": "critical",
      "title": "Critical security issue",
      "description": "Critical finding",
      "evidence": "test",
      "remediation": "Fix immediately",
      "auto_fix": ""
    },
    {
      "id": "CHK-CFG-011",
      "severity": "warn",
      "title": "Warning finding",
      "description": "Warning",
      "evidence": "test",
      "remediation": "Fix it",
      "auto_fix": ""
    }
  ]'

  # Run clawpinch (should exit 1 for critical, not 2 for warn)
  local exit_code
  exit_code="$(run_clawpinch_with_exit_code "")"

  if [[ "$exit_code" -eq 1 ]]; then
    assert_pass "Mixed findings: critical causes exit 1 (not 2 for warnings)"
    return 0
  else
    assert_fail "Mixed findings critical priority" "Expected exit code 1, got $exit_code"
    return 1
  fi
}

# ─── Test: Combined Flags ─────────────────────────────────────────────────────

test_combined_flags() {
  log_info "Test 15: Combined --severity-threshold and --fail-on flags"

  # Prepare for test
  prepare_test

  # Create a scanner with info findings
  create_mock_scanner "combined" '[
    {
      "id": "CHK-CFG-012",
      "severity": "info",
      "title": "Info finding",
      "description": "Information",
      "evidence": "test",
      "remediation": "Note this",
      "auto_fix": ""
    }
  ]'

  # Run with both flags: threshold=critical (would ignore info) but fail-on matches
  local exit_code
  exit_code="$(run_clawpinch_with_exit_code "--severity-threshold critical --fail-on CHK-CFG-012")"

  if [[ "$exit_code" -eq 1 ]]; then
    assert_pass "Combined flags: --fail-on overrides --severity-threshold"
    return 0
  else
    assert_fail "Combined flags" "Expected exit code 1, got $exit_code"
    return 1
  fi
}

# ─── Main Test Suite ──────────────────────────────────────────────────────────

main() {
  printf "\n${BLUE}═══════════════════════════════════════════════════════════════${RESET}\n"
  printf "${BLUE}  ClawPinch Exit Code Integration Test Suite${RESET}\n"
  printf "${BLUE}═══════════════════════════════════════════════════════════════${RESET}\n\n"

  # Set up test environment
  setup_test_environment

  # Ensure cleanup on exit
  trap cleanup_test_environment EXIT

  # Run tests
  test_exit_code_0_clean
  test_exit_code_0_below_threshold
  test_exit_code_1_critical
  test_exit_code_2_warnings_default
  test_exit_code_2_warnings_explicit
  test_exit_code_2_info
  test_exit_code_0_info_below_threshold
  test_exit_code_2_ok
  test_exit_code_3_scan_error
  test_fail_on_matching
  test_fail_on_non_matching
  test_fail_on_multiple
  test_critical_always_wins
  test_mixed_findings_critical_priority
  test_combined_flags

  # Print summary
  printf "\n${BLUE}═══════════════════════════════════════════════════════════════${RESET}\n"
  printf "${BLUE}  Test Summary${RESET}\n"
  printf "${BLUE}═══════════════════════════════════════════════════════════════${RESET}\n"
  printf "  Total tests:  %d\n" "$TESTS_RUN"
  printf "  ${GREEN}Passed:       %d${RESET}\n" "$TESTS_PASSED"
  if [[ "$TESTS_FAILED" -gt 0 ]]; then
    printf "  ${RED}Failed:       %d${RESET}\n" "$TESTS_FAILED"
  else
    printf "  ${GREEN}Failed:       %d${RESET}\n" "$TESTS_FAILED"
  fi
  printf "${BLUE}═══════════════════════════════════════════════════════════════${RESET}\n\n"

  # Exit with appropriate code
  if [[ "$TESTS_FAILED" -eq 0 ]]; then
    log_success "All tests passed!"
    exit 0
  else
    log_error "Some tests failed!"
    exit 1
  fi
}

main "$@"
