#!/usr/bin/env bash
# scan_network.sh - Network exposure and firewall posture scanner for OpenClaw
# Checks listening ports, firewall status, and network configuration against
# the OpenClaw config to identify security issues.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# Source common helpers if available, otherwise define fallbacks
if [[ -f "$PROJECT_ROOT/helpers/common.sh" ]]; then
  # shellcheck source=../helpers/common.sh
  source "$PROJECT_ROOT/helpers/common.sh"
else
  # --- Fallback helper functions ---
  _FINDINGS="[]"

  emit_finding() {
    local id="$1" severity="$2" title="$3" description="$4" evidence="${5:-}" remediation="${6:-}"
    local json
    json=$(printf '{"id":"%s","severity":"%s","title":"%s","description":"%s","evidence":"%s","remediation":"%s"}' \
      "$id" "$severity" \
      "$(echo "$title" | sed 's/"/\\"/g')" \
      "$(echo "$description" | sed 's/"/\\"/g')" \
      "$(echo "$evidence" | sed 's/"/\\"/g')" \
      "$(echo "$remediation" | sed 's/"/\\"/g')")
    _FINDINGS=$(echo "$_FINDINGS" | sed "s/\]$/,$json]/" | sed 's/\[,/[/')
  }

  output_findings() {
    echo "$_FINDINGS"
  }

  log_debug() {
    if [[ "${CLAWPINCH_DEBUG:-0}" == "1" ]]; then
      echo "[DEBUG] $*" >&2
    fi
  }

  detect_os() {
    case "$(uname -s)" in
      Darwin) echo "macos" ;;
      Linux)  echo "linux" ;;
      *)      echo "unknown" ;;
    esac
  }
fi

# --- Configuration parsing ---

# Locate the OpenClaw config file. Check common locations.
find_openclaw_config() {
  local candidates=(
    "$PROJECT_ROOT/config.yaml"
    "$PROJECT_ROOT/config.yml"
    "$PROJECT_ROOT/config.json"
    "$PROJECT_ROOT/openclaw.yaml"
    "$PROJECT_ROOT/openclaw.yml"
    "$PROJECT_ROOT/openclaw.json"
    "$HOME/.openclaw/config.yaml"
    "$HOME/.openclaw/config.yml"
    "$HOME/.openclaw/config.json"
    "/etc/openclaw/config.yaml"
    "/etc/openclaw/config.yml"
    "/etc/openclaw/config.json"
  )
  # Also accept OPENCLAW_CONFIG env var
  if [[ -n "${OPENCLAW_CONFIG:-}" && -f "$OPENCLAW_CONFIG" ]]; then
    echo "$OPENCLAW_CONFIG"
    return 0
  fi
  for candidate in "${candidates[@]}"; do
    if [[ -f "$candidate" ]]; then
      echo "$candidate"
      return 0
    fi
  done
  return 1
}

# Extract a value from a YAML/JSON config. Simple grep-based parser for
# flat key: value structures. Falls back to defaults if not found.
config_get() {
  local key="$1" default="${2:-}" config_file="${3:-}"
  if [[ -z "$config_file" || ! -f "$config_file" ]]; then
    echo "$default"
    return
  fi
  local value=""
  # Try JSON-style: "key": value or "key": "value"
  value=$(grep -E "\"${key}\"\\s*:" "$config_file" 2>/dev/null | head -1 | sed 's/.*:\s*//;s/[",]//g;s/^[[:space:]]*//;s/[[:space:]]*$//' || true)
  if [[ -z "$value" ]]; then
    # Try YAML-style: key: value
    value=$(grep -E "^[[:space:]]*${key}\\s*:" "$config_file" 2>/dev/null | head -1 | sed 's/.*:\s*//;s/[",]//g;s/^[[:space:]]*//;s/[[:space:]]*$//' || true)
  fi
  if [[ -z "$value" ]]; then
    echo "$default"
  else
    echo "$value"
  fi
}

# --- Port and network utilities ---

# Get listening TCP ports. Returns lines of: BIND_ADDR:PORT PID/PROGRAM
get_listening_ports() {
  local os
  os=$(detect_os)
  case "$os" in
    macos)
      # lsof output: COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME
      # NAME is like *:8080, 127.0.0.1:8080, or [::1]:8080
      lsof -iTCP -sTCP:LISTEN -P -n 2>/dev/null | awk 'NR>1 {
        name = $9;
        # Find last colon to split address:port (handles IPv6 brackets)
        n = split(name, parts, ":");
        port = parts[n];
        if (n == 2) {
          addr = parts[1];
        } else {
          # IPv6: rejoin all but last part
          addr = parts[1];
          for (i = 2; i < n; i++) addr = addr ":" parts[i];
        }
        # Normalize addresses
        if (addr == "*") addr = "0.0.0.0";
        gsub(/\[|\]/, "", addr);
        if (addr == "::1") addr = "127.0.0.1";
        if (addr == "::" || addr == "::0") addr = "0.0.0.0";
        printf "%s:%s %s/%s\n", addr, port, $2, $1
      }' | sort -u
      ;;
    linux)
      # ss output: State Recv-Q Send-Q Local Address:Port Peer Address:Port Process
      ss -tlnp 2>/dev/null | awk 'NR>1 {
        local_addr = $4;
        n = split(local_addr, parts, ":");
        port = parts[n];
        if (n == 2) {
          addr = parts[1];
        } else {
          addr = parts[1];
          for (i = 2; i < n; i++) addr = addr ":" parts[i];
        }
        if (addr == "" || addr == "*") addr = "0.0.0.0";
        gsub(/\[|\]/, "", addr);
        if (addr == "::1") addr = "127.0.0.1";
        if (addr == "::" || addr == "::0") addr = "0.0.0.0";
        # Extract pid/program from the Process column
        proc = $NF;
        gsub(/.*pid=/, "", proc);
        gsub(/,.*/, "", proc);
        printf "%s:%s %s\n", addr, port, proc
      }' | sort -u
      ;;
    *)
      log_debug "Unsupported OS for port enumeration"
      ;;
  esac
}

# Check if a specific port is listening on a wildcard (0.0.0.0 or ::) address
is_port_exposed() {
  local port="$1" listening_data="$2"
  echo "$listening_data" | grep -E "(0\.0\.0\.0|::|\*):${port}\b" >/dev/null 2>&1
}

# Check if a specific port is listening at all
is_port_listening() {
  local port="$1" listening_data="$2"
  echo "$listening_data" | grep -E ":${port}\b" >/dev/null 2>&1
}

# Get the bind address for a specific port
get_bind_address() {
  local port="$1" listening_data="$2"
  echo "$listening_data" | grep -E ":${port}\b" | head -1 | cut -d: -f1
}

# Get the process info for a specific port
get_process_for_port() {
  local port="$1" listening_data="$2"
  echo "$listening_data" | grep -E ":${port}\b" | head -1 | awk '{print $2}'
}

# Count how many distinct processes are listening on a given port
count_listeners_on_port() {
  local port="$1" listening_data="$2"
  echo "$listening_data" | grep -E ":${port}\b" | awk '{print $2}' | sort -u | wc -l | tr -d ' '
}

# --- Firewall detection ---

check_firewall_active() {
  local os
  os=$(detect_os)
  case "$os" in
    macos)
      # Check macOS Application Firewall via socketfilterfw
      local fw_status
      fw_status=$(/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate 2>/dev/null || true)
      if echo "$fw_status" | grep -qi "enabled"; then
        echo "active:macos-alf"
        return 0
      fi
      # Check pf (packet filter)
      if pfctl -s info 2>/dev/null | grep -qi "status: enabled"; then
        echo "active:pf"
        return 0
      fi
      echo "inactive"
      return 1
      ;;
    linux)
      # Check ufw
      if command -v ufw >/dev/null 2>&1; then
        if ufw status 2>/dev/null | grep -qi "status: active"; then
          echo "active:ufw"
          return 0
        fi
      fi
      # Check firewalld
      if command -v firewall-cmd >/dev/null 2>&1; then
        if firewall-cmd --state 2>/dev/null | grep -qi "running"; then
          echo "active:firewalld"
          return 0
        fi
      fi
      # Check iptables (fallback - check if any non-default rules exist)
      if command -v iptables >/dev/null 2>&1; then
        local rule_count
        rule_count=$(iptables -L 2>/dev/null | grep -cv "^Chain\|^target\|^$" || echo "0")
        if [[ "$rule_count" -gt 0 ]]; then
          echo "active:iptables"
          return 0
        fi
      fi
      # Check nftables
      if command -v nft >/dev/null 2>&1; then
        local nft_rules
        nft_rules=$(nft list ruleset 2>/dev/null | wc -l | tr -d ' ')
        if [[ "$nft_rules" -gt 0 ]]; then
          echo "active:nftables"
          return 0
        fi
      fi
      echo "inactive"
      return 1
      ;;
    *)
      echo "unknown"
      return 1
      ;;
  esac
}

# --- Main checks ---

run_checks() {
  local config_file=""
  config_file=$(find_openclaw_config 2>/dev/null || true)
  log_debug "Config file: ${config_file:-<not found>}"

  # Read config values with defaults
  local gateway_port control_ui_port canvas_port cdp_port trusted_proxies
  gateway_port=$(config_get "gatewayPort" "3000" "$config_file")
  control_ui_port=$(config_get "controlUIPort" "3001" "$config_file")
  canvas_port=$(config_get "canvasPort" "5900" "$config_file")
  cdp_port=$(config_get "cdpPort" "9222" "$config_file")
  trusted_proxies=$(config_get "trustedProxies" "" "$config_file")

  log_debug "Gateway port: $gateway_port"
  log_debug "Control UI port: $control_ui_port"
  log_debug "Canvas port: $canvas_port"
  log_debug "CDP port: $cdp_port"

  # Collect listening ports once
  local listening_data
  listening_data=$(get_listening_ports)
  log_debug "Listening ports data:\n$listening_data"

  # CHK-NET-001: Gateway port listening on 0.0.0.0
  if is_port_listening "$gateway_port" "$listening_data"; then
    if is_port_exposed "$gateway_port" "$listening_data"; then
      local proc
      proc=$(get_process_for_port "$gateway_port" "$listening_data")
      emit_finding "CHK-NET-001" "critical" \
        "Gateway port $gateway_port bound to 0.0.0.0" \
        "The OpenClaw gateway is listening on all interfaces (0.0.0.0:$gateway_port), making it accessible from any network." \
        "Port $gateway_port bound to 0.0.0.0 by process $proc" \
        "Bind the gateway to 127.0.0.1 in the OpenClaw config (set gatewayHost: 127.0.0.1) unless external access is intentional and protected by a reverse proxy."
    else
      local bind_addr
      bind_addr=$(get_bind_address "$gateway_port" "$listening_data")
      emit_finding "CHK-NET-001" "ok" \
        "Gateway port $gateway_port bound to $bind_addr" \
        "The OpenClaw gateway is correctly bound to a local address ($bind_addr:$gateway_port)." \
        "Port $gateway_port bound to $bind_addr" \
        ""
    fi
  else
    emit_finding "CHK-NET-001" "info" \
      "Gateway port $gateway_port not listening" \
      "No process is currently listening on the configured gateway port $gateway_port. OpenClaw may not be running." \
      "No listener on port $gateway_port" \
      "Start the OpenClaw gateway if it should be running."
  fi

  # CHK-NET-002: Control UI port exposed externally
  if is_port_listening "$control_ui_port" "$listening_data"; then
    if is_port_exposed "$control_ui_port" "$listening_data"; then
      local proc
      proc=$(get_process_for_port "$control_ui_port" "$listening_data")
      emit_finding "CHK-NET-002" "critical" \
        "Control UI port $control_ui_port exposed externally" \
        "The OpenClaw control UI is listening on all interfaces (0.0.0.0:$control_ui_port). This admin interface should never be publicly accessible." \
        "Port $control_ui_port bound to 0.0.0.0 by process $proc" \
        "Bind the control UI to 127.0.0.1 (set controlUIHost: 127.0.0.1) and access it only via SSH tunnel or VPN."
    else
      local bind_addr
      bind_addr=$(get_bind_address "$control_ui_port" "$listening_data")
      emit_finding "CHK-NET-002" "ok" \
        "Control UI port $control_ui_port bound to $bind_addr" \
        "The control UI is correctly bound to a local address ($bind_addr:$control_ui_port)." \
        "Port $control_ui_port bound to $bind_addr" \
        ""
    fi
  else
    emit_finding "CHK-NET-002" "info" \
      "Control UI port $control_ui_port not listening" \
      "No process is currently listening on the configured control UI port $control_ui_port." \
      "No listener on port $control_ui_port" \
      ""
  fi

  # CHK-NET-003: Canvas host port exposed
  if is_port_listening "$canvas_port" "$listening_data"; then
    if is_port_exposed "$canvas_port" "$listening_data"; then
      local proc
      proc=$(get_process_for_port "$canvas_port" "$listening_data")
      emit_finding "CHK-NET-003" "warn" \
        "Canvas host port $canvas_port exposed externally" \
        "The canvas host port is listening on all interfaces (0.0.0.0:$canvas_port). This exposes the canvas streaming service to the network." \
        "Port $canvas_port bound to 0.0.0.0 by process $proc" \
        "Bind the canvas host to 127.0.0.1 (set canvasHost: 127.0.0.1) unless remote canvas access is required."
    else
      local bind_addr
      bind_addr=$(get_bind_address "$canvas_port" "$listening_data")
      emit_finding "CHK-NET-003" "ok" \
        "Canvas host port $canvas_port bound to $bind_addr" \
        "The canvas host is correctly bound to a local address ($bind_addr:$canvas_port)." \
        "Port $canvas_port bound to $bind_addr" \
        ""
    fi
  else
    emit_finding "CHK-NET-003" "info" \
      "Canvas host port $canvas_port not listening" \
      "No process is currently listening on the configured canvas port $canvas_port." \
      "No listener on port $canvas_port" \
      ""
  fi

  # CHK-NET-004: No firewall active
  local fw_result
  if fw_result=$(check_firewall_active 2>/dev/null); then
    emit_finding "CHK-NET-004" "ok" \
      "Firewall is active (${fw_result#active:})" \
      "A firewall is active on this system using ${fw_result#active:}." \
      "$fw_result" \
      ""
  else
    emit_finding "CHK-NET-004" "warn" \
      "No active firewall detected" \
      "No active firewall was detected on this system. Without a firewall, all listening ports are accessible from the network." \
      "Firewall status: ${fw_result:-inactive}" \
      "Enable a host firewall: on macOS use the built-in Application Firewall or pf; on Linux use ufw, firewalld, or nftables."
  fi

  # CHK-NET-005: Gateway port accessible from non-loopback interface
  if is_port_listening "$gateway_port" "$listening_data"; then
    if is_port_exposed "$gateway_port" "$listening_data"; then
      # Gateway is on 0.0.0.0; check if non-loopback interfaces exist with routable IPs
      local non_lo_ips
      local os
      os=$(detect_os)
      case "$os" in
        macos)
          non_lo_ips=$(ifconfig 2>/dev/null | grep "inet " | grep -v "127.0.0.1" | awk '{print $2}' | tr '\n' ', ' | sed 's/,$//')
          ;;
        linux)
          non_lo_ips=$(ip -4 addr show 2>/dev/null | grep "inet " | grep -v "127.0.0.1" | awk '{print $2}' | cut -d/ -f1 | tr '\n' ', ' | sed 's/,$//')
          ;;
        *)
          non_lo_ips=""
          ;;
      esac
      if [[ -n "$non_lo_ips" ]]; then
        emit_finding "CHK-NET-005" "critical" \
          "Gateway port $gateway_port reachable on non-loopback interfaces" \
          "The gateway is bound to 0.0.0.0 and this host has non-loopback addresses ($non_lo_ips). The gateway is reachable from external networks." \
          "Non-loopback IPs: $non_lo_ips; gateway on 0.0.0.0:$gateway_port" \
          "Bind the gateway to 127.0.0.1 or configure firewall rules to restrict access to port $gateway_port."
      else
        emit_finding "CHK-NET-005" "ok" \
          "Gateway on 0.0.0.0 but no non-loopback interfaces found" \
          "The gateway is on 0.0.0.0 but no non-loopback network interfaces with IPv4 addresses were detected." \
          "No non-loopback IPs detected" \
          ""
      fi
    else
      emit_finding "CHK-NET-005" "ok" \
        "Gateway port $gateway_port not exposed to non-loopback interfaces" \
        "The gateway is bound to a loopback address and is not reachable from external networks." \
        "Gateway bound to $(get_bind_address "$gateway_port" "$listening_data")" \
        ""
    fi
  else
    emit_finding "CHK-NET-005" "info" \
      "Gateway not listening - skipping non-loopback check" \
      "The gateway port $gateway_port is not active, so non-loopback exposure cannot be assessed." \
      "No listener on port $gateway_port" \
      ""
  fi

  # CHK-NET-006: Browser CDP port exposed
  if is_port_listening "$cdp_port" "$listening_data"; then
    if is_port_exposed "$cdp_port" "$listening_data"; then
      local proc
      proc=$(get_process_for_port "$cdp_port" "$listening_data")
      emit_finding "CHK-NET-006" "warn" \
        "Browser CDP port $cdp_port exposed externally" \
        "The Chrome DevTools Protocol port is listening on all interfaces (0.0.0.0:$cdp_port). CDP allows full browser control and can be exploited for remote code execution." \
        "Port $cdp_port bound to 0.0.0.0 by process $proc" \
        "Bind CDP to 127.0.0.1 by launching Chrome/Chromium with --remote-debugging-address=127.0.0.1 or set cdpHost: 127.0.0.1 in the OpenClaw config."
    else
      local bind_addr
      bind_addr=$(get_bind_address "$cdp_port" "$listening_data")
      emit_finding "CHK-NET-006" "ok" \
        "CDP port $cdp_port bound to $bind_addr" \
        "The Chrome DevTools Protocol port is correctly bound to a local address ($bind_addr:$cdp_port)." \
        "Port $cdp_port bound to $bind_addr" \
        ""
    fi
  else
    emit_finding "CHK-NET-006" "info" \
      "CDP port $cdp_port not listening" \
      "No process is currently listening on the configured CDP port $cdp_port." \
      "No listener on port $cdp_port" \
      ""
  fi

  # CHK-NET-007: trustedProxies not configured when behind reverse proxy
  # Heuristic: if gateway is on 127.0.0.1 but we see a reverse proxy (nginx, caddy, haproxy, traefik)
  # listening on port 80 or 443, then trustedProxies should be set.
  local reverse_proxy_detected=false
  local proxy_name=""
  if echo "$listening_data" | grep -E ":(80|443)\b" | grep -qiE "nginx|caddy|haproxy|traefik|httpd|apache" 2>/dev/null; then
    reverse_proxy_detected=true
    proxy_name=$(echo "$listening_data" | grep -E ":(80|443)\b" | head -1 | awk '{print $2}')
  fi
  # Also check for common proxy processes running
  if ! $reverse_proxy_detected; then
    local os
    os=$(detect_os)
    local proxy_procs
    case "$os" in
      macos)
        proxy_procs=$(ps aux 2>/dev/null | grep -iE "nginx|caddy|haproxy|traefik" | grep -v grep || true)
        ;;
      linux)
        proxy_procs=$(ps aux 2>/dev/null | grep -iE "nginx|caddy|haproxy|traefik" | grep -v grep || true)
        ;;
      *)
        proxy_procs=""
        ;;
    esac
    if [[ -n "$proxy_procs" ]]; then
      reverse_proxy_detected=true
      proxy_name=$(echo "$proxy_procs" | head -1 | awk '{print $11}')
    fi
  fi

  if $reverse_proxy_detected && [[ -z "$trusted_proxies" ]]; then
    emit_finding "CHK-NET-007" "info" \
      "trustedProxies not configured but reverse proxy detected" \
      "A reverse proxy process ($proxy_name) was detected, but trustedProxies is not set in the OpenClaw config. Without this setting, the gateway cannot reliably determine client IP addresses from X-Forwarded-For headers." \
      "Reverse proxy detected: $proxy_name; trustedProxies: <not set>" \
      "Set trustedProxies in the OpenClaw config to the IP address(es) of your reverse proxy (e.g., trustedProxies: [\"127.0.0.1\"])."
  elif $reverse_proxy_detected && [[ -n "$trusted_proxies" ]]; then
    emit_finding "CHK-NET-007" "ok" \
      "trustedProxies configured with reverse proxy present" \
      "A reverse proxy is detected and trustedProxies is configured ($trusted_proxies)." \
      "trustedProxies: $trusted_proxies" \
      ""
  else
    emit_finding "CHK-NET-007" "ok" \
      "No reverse proxy detected" \
      "No reverse proxy was detected, so trustedProxies configuration is not required." \
      "No reverse proxy process found" \
      ""
  fi

  # CHK-NET-008: Multiple OpenClaw processes listening (legacy + current)
  if is_port_listening "$gateway_port" "$listening_data"; then
    local listener_count
    listener_count=$(count_listeners_on_port "$gateway_port" "$listening_data")
    if [[ "$listener_count" -gt 1 ]]; then
      local procs
      procs=$(echo "$listening_data" | grep -E ":${gateway_port}\b" | awk '{print $2}' | sort -u | tr '\n' ', ' | sed 's/,$//')
      emit_finding "CHK-NET-008" "warn" \
        "Multiple processes listening on gateway port $gateway_port" \
        "Found $listener_count distinct processes listening on the gateway port $gateway_port. This may indicate both a legacy and current OpenClaw instance are running simultaneously, which can cause routing conflicts and security issues." \
        "Processes on port $gateway_port: $procs" \
        "Stop the legacy OpenClaw process. Use 'kill <PID>' on the older process, or check for stale systemd/launchd services."
    else
      emit_finding "CHK-NET-008" "ok" \
        "Single process on gateway port $gateway_port" \
        "Only one process is listening on the gateway port, as expected." \
        "1 listener on port $gateway_port" \
        ""
    fi
  else
    emit_finding "CHK-NET-008" "info" \
      "Gateway not listening - skipping duplicate process check" \
      "The gateway port $gateway_port is not active, so duplicate process detection cannot be performed." \
      "No listener on port $gateway_port" \
      ""
  fi

  # Output final JSON
  output_findings
}

# --- Entry point ---
run_checks
