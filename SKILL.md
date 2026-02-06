# ClawPinch -- OpenClaw Security Audit Skill

## Metadata

| Field       | Value                                                        |
|-------------|--------------------------------------------------------------|
| **Name**    | ClawPinch                                                    |
| **Version** | 0.1.0                                                        |
| **Author**  | ClawPinch Contributors                                       |
| **License** | MIT                                                          |
| **Platform**| macOS, Linux                                                 |

## Description

Comprehensive security audit toolkit for OpenClaw deployments. ClawPinch
inspects gateway configuration, installed skills, channel bindings, cron
schedules, network exposure, secrets hygiene, supply-chain integrity, and
known CVEs -- then produces a prioritised report with remediation steps.

## Goal

Audit an OpenClaw installation for:

- Misconfigurations that weaken the security posture
- Exposed or hardcoded secrets (API keys, tokens, passwords)
- Malicious or over-privileged skills
- Network services reachable from untrusted interfaces
- Weak or missing cron sandbox controls
- Permissions that violate least-privilege
- Supply-chain risks (unsigned skills, compromised registries)
- Known CVEs in the installed OpenClaw version

## Safety Rules

1. **No remote execution.** ClawPinch runs entirely on the local machine. It
   never opens outbound connections except to check version metadata from the
   official OpenClaw registry.
2. **No system modifications without consent.** Scanners are read-only by
   default. Auto-fix commands are only printed, never executed, unless the
   operator explicitly passes `--fix`.
3. **Always redact secrets.** Any secret found during scanning is truncated to
   its first 4 characters followed by `****` in all output.
4. **Treat all skills as untrusted.** Skill manifest analysis applies a
   deny-by-default policy -- every declared permission must be justified.
5. **No privilege escalation.** ClawPinch never requests `sudo` or elevated
   permissions. If a check requires elevated access it is skipped with a
   warning.
6. **Findings are advisory.** Output is informational. The operator decides
   whether to act on findings.

## Usage

```bash
# Standard scan (fast, covers the most common issues)
bash clawpinch.sh

# Deep scan (slower, includes supply-chain hash verification and full
# skill decompilation)
bash clawpinch.sh --deep

# Machine-readable JSON output
bash clawpinch.sh --json

# Target a specific config directory
bash clawpinch.sh --config-dir /path/to/openclaw/config

# Run only specific scanner categories
bash clawpinch.sh --scanners config,secrets,network

# Print suggested fix commands (does NOT execute them)
bash clawpinch.sh --fix
```

## Check Categories

### Configuration (CHK-CFG-001 .. CHK-CFG-010)

| ID            | Title                                       |
|---------------|---------------------------------------------|
| CHK-CFG-001   | Gateway listening on 0.0.0.0                |
| CHK-CFG-002   | Gateway auth disabled                       |
| CHK-CFG-003   | TLS not enabled on gateway                  |
| CHK-CFG-004   | Debug mode enabled in production            |
| CHK-CFG-005   | Config file world-readable                  |
| CHK-CFG-006   | Default admin credentials unchanged         |
| CHK-CFG-007   | Permissive CORS policy (wildcard origin)    |
| CHK-CFG-008   | Session timeout exceeds 24 hours            |
| CHK-CFG-009   | Rate limiting not configured                |
| CHK-CFG-010   | Audit logging disabled                      |

### Secrets (CHK-SEC-001 .. CHK-SEC-008)

| ID            | Title                                       |
|---------------|---------------------------------------------|
| CHK-SEC-001   | API key found in config file                |
| CHK-SEC-002   | Hardcoded password in skill manifest        |
| CHK-SEC-003   | Private key in config directory             |
| CHK-SEC-004   | .env file with secrets in working dir       |
| CHK-SEC-005   | Token in shell history                      |
| CHK-SEC-006   | Unencrypted credential store                |
| CHK-SEC-007   | Secret passed via environment variable      |
| CHK-SEC-008   | Git repo contains committed secrets         |

### Network (CHK-NET-001 .. CHK-NET-008)

| ID            | Title                                       |
|---------------|---------------------------------------------|
| CHK-NET-001   | Gateway port exposed to public interface    |
| CHK-NET-002   | WebSocket endpoint lacks authentication     |
| CHK-NET-003   | HTTP used instead of HTTPS                  |
| CHK-NET-004   | Proxy misconfiguration leaks internal IPs   |
| CHK-NET-005   | DNS rebinding protection missing            |
| CHK-NET-006   | Open redirect in auth callback              |
| CHK-NET-007   | Server headers disclose version info        |
| CHK-NET-008   | Unrestricted outbound from skill sandbox    |

### Skills (CHK-SKL-001 .. CHK-SKL-010)

| ID            | Title                                       |
|---------------|---------------------------------------------|
| CHK-SKL-001   | Skill requests filesystem write access      |
| CHK-SKL-002   | Skill requests network access               |
| CHK-SKL-003   | Skill requests shell execution              |
| CHK-SKL-004   | Skill not signed                            |
| CHK-SKL-005   | Skill has known malicious hash              |
| CHK-SKL-006   | Skill requests access to other skills       |
| CHK-SKL-007   | Skill manifest references external URL      |
| CHK-SKL-008   | Skill uses eval() or exec() patterns        |
| CHK-SKL-009   | Skill version pinned to mutable tag         |
| CHK-SKL-010   | Skill overrides safety rules                |

### Permissions (CHK-PRM-001 .. CHK-PRM-008)

| ID            | Title                                       |
|---------------|---------------------------------------------|
| CHK-PRM-001   | Skill granted admin-level permissions       |
| CHK-PRM-002   | Wildcard permission grant                   |
| CHK-PRM-003   | Channel can invoke privileged skills        |
| CHK-PRM-004   | No permission boundary between skills       |
| CHK-PRM-005   | User role allows skill installation         |
| CHK-PRM-006   | API token has excessive scopes              |
| CHK-PRM-007   | Cross-tenant access not restricted          |
| CHK-PRM-008   | Permission changes not audited              |

### Cron (CHK-CRN-001 .. CHK-CRN-006)

| ID            | Title                                       |
|---------------|---------------------------------------------|
| CHK-CRN-001   | Cron job runs as root                       |
| CHK-CRN-002   | Cron job executes un-reviewed skill         |
| CHK-CRN-003   | Cron schedule allows rapid-fire execution   |
| CHK-CRN-004   | Cron job lacks timeout                      |
| CHK-CRN-005   | Cron job output not captured                |
| CHK-CRN-006   | Cron job has network access                 |

### CVE (CHK-CVE-001 .. CHK-CVE-005)

| ID            | Title                                       |
|---------------|---------------------------------------------|
| CHK-CVE-001   | OpenClaw version vulnerable to known CVE    |
| CHK-CVE-002   | Gateway auth bypass (CVE-2026-25253)        |
| CHK-CVE-003   | Docker sandbox escape (CVE-2026-24763)      |
| CHK-CVE-004   | SSH path injection (CVE-2026-25157)         |
| CHK-CVE-005   | Outdated dependency with known vuln         |

### Supply Chain (CHK-SUP-001 .. CHK-SUP-008)

| ID            | Title                                       |
|---------------|---------------------------------------------|
| CHK-SUP-001   | Skill installed from untrusted registry     |
| CHK-SUP-002   | Skill hash does not match registry          |
| CHK-SUP-003   | Registry URL uses HTTP, not HTTPS           |
| CHK-SUP-004   | Skill depends on deprecated package         |
| CHK-SUP-005   | Skill pulls transitive dependency at runtime|
| CHK-SUP-006   | No lockfile for installed skills            |
| CHK-SUP-007   | Registry certificate not pinned             |
| CHK-SUP-008   | Skill author identity not verified          |

## Workflow

```
  collect          analyze          report          suggest
 ┌──────────┐    ┌──────────┐    ┌──────────┐    ┌──────────┐
 │ Read      │───▶│ Run      │───▶│ Rank by  │───▶│ Print    │
 │ config,   │    │ scanners │    │ severity │    │ findings │
 │ skills,   │    │ against  │    │ & dedup  │    │ & fixes  │
 │ network   │    │ rules    │    │          │    │          │
 └──────────┘    └──────────┘    └──────────┘    └──────────┘
```

1. **Collect** -- Locate the OpenClaw config directory. Enumerate installed
   skills, channel bindings, cron entries, and running gateway processes.
2. **Analyze** -- Execute each scanner category. Every check emits structured
   JSON findings via `emit_finding()`.
3. **Report** -- Aggregate findings, de-duplicate, sort by severity
   (critical > warn > info > ok), and render to the selected output format.
4. **Suggest** -- For each finding with a known remediation, print a
   human-readable fix. With `--fix`, also print executable shell commands.

## Output Format

Each finding follows the schema defined in `scripts/helpers/common.sh`:

```json
{
  "id":          "CHK-CFG-001",
  "severity":    "critical",
  "title":       "Gateway listening on 0.0.0.0",
  "description": "The gateway is bound to all interfaces, exposing it to the network.",
  "evidence":    "bindAddress: 0.0.0.0:3000",
  "remediation": "Set bindAddress to 127.0.0.1 in openclaw.json",
  "auto_fix":    "jq '.gateway.bindAddress = \"127.0.0.1:3000\"' openclaw.json > tmp && mv tmp openclaw.json"
}
```

## Dependencies

- **Required:** `bash` >= 4.0, `jq`
- **Optional:** `openssl` (TLS checks), `nmap` / `ss` (network checks),
  `sha256sum` / `shasum` (supply-chain hash verification)
