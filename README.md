```
      ██████╗██╗      █████╗ ██╗    ██╗██████╗ ██╗███╗   ██╗ ██████╗██╗  ██╗
     ██╔════╝██║     ██╔══██╗██║    ██║██╔══██╗██║████╗  ██║██╔════╝██║  ██║
     ██║     ██║     ███████║██║ █╗ ██║██████╔╝██║██╔██╗ ██║██║     ███████║
     ██║     ██║     ██╔══██║██║███╗██║██╔═══╝ ██║██║╚██╗██║██║     ██╔══██║
     ╚██████╗███████╗██║  ██║╚███╔███╔╝██║     ██║██║ ╚████║╚██████╗██║  ██║
      ╚═════╝╚══════╝╚═╝  ╚═╝ ╚══╝╚══╝ ╚═╝     ╚═╝╚═╝  ╚═══╝ ╚═════╝╚═╝  ╚═╝

            /)/)
           ( .  .)      🦀  "Don't get pinched."
          ╭(  >  <>
         /|________|\        Security audit toolkit for OpenClaw
        / |  |    | |\
       *  |__|____|_| *
```

[![npm](https://img.shields.io/npm/v/clawpinch)](https://www.npmjs.com/package/clawpinch)
![Version](https://img.shields.io/badge/version-1.0.0-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Platform](https://img.shields.io/badge/platform-macOS%20%7C%20Linux-lightgrey)

---

**ClawPinch** audits your OpenClaw deployment for misconfigurations, exposed
secrets, malicious skills, network exposure, supply-chain risks, and known CVEs
-- then tells you exactly how to fix what it finds.

Inspired by [ClawdStrike](https://clawdstrike.ai) by Cantina. ClawPinch goes
deeper: more checks, structured JSON output, auto-fix suggestions, and a full
threat model.

---

## Install

### Option 1: npx (zero install, recommended)

```bash
npx clawpinch
```

### Option 2: Global install

```bash
npm install -g clawpinch
clawpinch
```

### Option 3: OpenClaw skill

```bash
npx skills add https://github.com/MikeeBuilds/clawpinch --skill clawpinch
```

Then move to your skills directory and run:

```bash
mv clawpinch ~/.openclaw/workspace/skills/
openclaw skill run clawpinch
```

### Option 4: From source

```bash
git clone https://github.com/MikeeBuilds/clawpinch.git
cd clawpinch
bash clawpinch.sh
```

### Requirements

- `bash` >= 4.0
- `jq` (install: `brew install jq` or `apt install jq`)
- Optional: `python3` (secrets scanner), `openssl`, `nmap`, `ss`, `sha256sum`

---

## Feature Comparison

| Feature                           | ClawPinch | ClawdStrike |
|-----------------------------------|:---------:|:-----------:|
| Config auditing                   |     Y     |      Y      |
| Secrets scanning                  |     Y     |      Y      |
| Network exposure checks           |     Y     |      Y      |
| Skill trust/signature analysis    |     Y     |      --     |
| Permission boundary auditing      |     Y     |      --     |
| Cron job safety checks            |     Y     |      --     |
| Known CVE detection               |     Y     |      Y      |
| Supply-chain integrity checks     |     Y     |      --     |
| Structured JSON output            |     Y     |      --     |
| Auto-fix suggestions              |     Y     |      --     |
| Threat model reference            |     Y     |      --     |
| Total checks                      |   63      |     ~20     |

---

## Usage

```bash
# Standard scan
bash clawpinch.sh

# Deep scan (supply-chain hash verification, skill decompilation)
bash clawpinch.sh --deep

# JSON output for CI/CD pipelines
bash clawpinch.sh --json

# Scan only specific categories
bash clawpinch.sh --scanners config,secrets,network

# Point at a custom config directory
bash clawpinch.sh --config-dir /path/to/openclaw/config

# Print auto-fix commands (read-only -- does not execute them)
bash clawpinch.sh --fix
```

---

## Example Output

```
 ══════════════════════════════════════════════════════════
   ClawPinch v0.1.0 -- OpenClaw Security Audit
 ══════════════════════════════════════════════════════════

 [info]  OpenClaw version: 2026.1.28
 [info]  Config: /home/user/.config/openclaw/openclaw.json
 [info]  Running 8 scanner categories (63 checks)...

 ── Config Scanner ──────────────────────────────────────
 [CRITICAL]  CHK-CFG-001  Gateway listening on 0.0.0.0
             Bind to 127.0.0.1 to restrict access.
 [CRITICAL]  CHK-CFG-002  Gateway auth disabled
             Enable requireAuth in openclaw.json.
 [WARN]      CHK-CFG-007  Permissive CORS policy (wildcard origin)
             Restrict allowedOrigins to specific domains.
 [OK]        CHK-CFG-003  TLS enabled on gateway

 ── Secrets Scanner ─────────────────────────────────────
 [CRITICAL]  CHK-SEC-001  API key found in config file
             Evidence: sk-a]4f****
             Move to a secrets manager or .env excluded from VCS.
 [OK]        CHK-SEC-003  No private keys in config directory

 ── Skills Scanner ──────────────────────────────────────
 [CRITICAL]  CHK-SKL-003  Skill "code-runner" requests shell execution
             Review skill permissions. Remove if not essential.
 [WARN]      CHK-SKL-004  Skill "weather-lookup" not signed
             Install only signed skills from trusted registries.
 [OK]        CHK-SKL-005  No known malicious skill hashes

 ── Network Scanner ─────────────────────────────────────
 [CRITICAL]  CHK-NET-001  Gateway port 3000 exposed to public interface
             Bind to localhost or place behind a reverse proxy.
 [OK]        CHK-NET-003  HTTPS in use

 ── CVE Scanner ─────────────────────────────────────────
 [CRITICAL]  CHK-CVE-002  Gateway auth bypass (CVE-2026-25253)
             Upgrade to OpenClaw >= 2026.1.29 immediately.
 [CRITICAL]  CHK-CVE-003  Docker sandbox escape (CVE-2026-24763)
             Upgrade to OpenClaw >= 2026.1.29 immediately.

 ══════════════════════════════════════════════════════════
   RESULTS: 6 critical | 2 warn | 0 info | 4 ok
   Run with --fix to see remediation commands.
 ══════════════════════════════════════════════════════════
```

---

## All Checks (63)

### Configuration (CHK-CFG)

| ID  | Check                                          | Severity |
|-----|------------------------------------------------|----------|
| 001 | Gateway listening on 0.0.0.0                   | Critical |
| 002 | Gateway auth disabled                          | Critical |
| 003 | TLS not enabled on gateway                     | Critical |
| 004 | Debug mode enabled in production               | Warn     |
| 005 | Config file world-readable                     | Warn     |
| 006 | Default admin credentials unchanged            | Critical |
| 007 | Permissive CORS policy (wildcard origin)       | Warn     |
| 008 | Session timeout exceeds 24 hours               | Warn     |
| 009 | Rate limiting not configured                   | Warn     |
| 010 | Audit logging disabled                         | Warn     |

### Secrets (CHK-SEC)

| ID  | Check                                          | Severity |
|-----|------------------------------------------------|----------|
| 001 | API key found in config file                   | Critical |
| 002 | Hardcoded password in skill manifest           | Critical |
| 003 | Private key in config directory                | Critical |
| 004 | .env file with secrets in working dir          | Warn     |
| 005 | Token in shell history                         | Warn     |
| 006 | Unencrypted credential store                   | Warn     |
| 007 | Secret passed via environment variable         | Info     |
| 008 | Git repo contains committed secrets            | Critical |

### Network (CHK-NET)

| ID  | Check                                          | Severity |
|-----|------------------------------------------------|----------|
| 001 | Gateway port exposed to public interface       | Critical |
| 002 | WebSocket endpoint lacks authentication        | Critical |
| 003 | HTTP used instead of HTTPS                     | Critical |
| 004 | Proxy misconfiguration leaks internal IPs      | Warn     |
| 005 | DNS rebinding protection missing               | Warn     |
| 006 | Open redirect in auth callback                 | Warn     |
| 007 | Server headers disclose version info           | Info     |
| 008 | Unrestricted outbound from skill sandbox       | Warn     |

### Skills (CHK-SKL)

| ID  | Check                                          | Severity |
|-----|------------------------------------------------|----------|
| 001 | Skill requests filesystem write access         | Warn     |
| 002 | Skill requests network access                  | Warn     |
| 003 | Skill requests shell execution                 | Critical |
| 004 | Skill not signed                               | Warn     |
| 005 | Skill has known malicious hash                 | Critical |
| 006 | Skill requests access to other skills          | Warn     |
| 007 | Skill manifest references external URL         | Warn     |
| 008 | Skill uses eval() or exec() patterns           | Critical |
| 009 | Skill version pinned to mutable tag            | Warn     |
| 010 | Skill overrides safety rules                   | Critical |

### Permissions (CHK-PRM)

| ID  | Check                                          | Severity |
|-----|------------------------------------------------|----------|
| 001 | Skill granted admin-level permissions          | Critical |
| 002 | Wildcard permission grant                      | Critical |
| 003 | Channel can invoke privileged skills           | Warn     |
| 004 | No permission boundary between skills          | Warn     |
| 005 | User role allows skill installation            | Warn     |
| 006 | API token has excessive scopes                 | Warn     |
| 007 | Cross-tenant access not restricted             | Critical |
| 008 | Permission changes not audited                 | Warn     |

### Cron (CHK-CRN)

| ID  | Check                                          | Severity |
|-----|------------------------------------------------|----------|
| 001 | Cron job runs as root                          | Critical |
| 002 | Cron job executes un-reviewed skill            | Warn     |
| 003 | Cron schedule allows rapid-fire execution      | Warn     |
| 004 | Cron job lacks timeout                         | Warn     |
| 005 | Cron job output not captured                   | Info     |
| 006 | Cron job has network access                    | Warn     |

### CVE (CHK-CVE)

| ID  | Check                                          | Severity |
|-----|------------------------------------------------|----------|
| 001 | OpenClaw version vulnerable to known CVE       | Critical |
| 002 | Gateway auth bypass (CVE-2026-25253)           | Critical |
| 003 | Docker sandbox escape (CVE-2026-24763)         | Critical |
| 004 | SSH path injection (CVE-2026-25157)            | Critical |
| 005 | Outdated dependency with known vuln            | Warn     |

### Supply Chain (CHK-SUP)

| ID  | Check                                          | Severity |
|-----|------------------------------------------------|----------|
| 001 | Skill installed from untrusted registry        | Critical |
| 002 | Skill hash does not match registry             | Critical |
| 003 | Registry URL uses HTTP, not HTTPS              | Critical |
| 004 | Skill depends on deprecated package            | Warn     |
| 005 | Skill pulls transitive dep at runtime          | Warn     |
| 006 | No lockfile for installed skills               | Warn     |
| 007 | Registry certificate not pinned                | Warn     |
| 008 | Skill author identity not verified             | Warn     |

---

## Project Structure

```
clawpinch/
  clawpinch.sh            # Main orchestrator
  scripts/
    helpers/
      common.sh           # Shared logging, finding emitter, config helpers
    scan_config.sh        # Configuration scanner
    scan_secrets.sh       # Secrets scanner
    scan_network.sh       # Network scanner
    scan_skills.sh        # Skills scanner
    scan_permissions.sh   # Permissions scanner
    scan_cron.sh          # Cron scanner
    scan_cve.sh           # CVE scanner
    scan_supply_chain.sh  # Supply chain scanner
  references/
    known-cves.json       # CVE database
    threat-model.md       # OpenClaw threat model
    check-catalog.md      # Full check catalog with remediation
  website/
    index.html            # Project landing page
  SKILL.md                # OpenClaw skill definition
  README.md               # This file
```

---

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b add-new-check`)
3. Add your check to the appropriate scanner in `scripts/`
4. Register the check ID in `references/check-catalog.md`
5. Run the test suite: `bash tests/run.sh`
6. Open a pull request

Check IDs follow the pattern `CHK-{CATEGORY}-{NNN}`. Pick the next available
number in the category.

---

## Credits

- Inspired by [ClawdStrike](https://clawdstrike.ai) by Cantina
- CVE data sourced from NVD and OpenClaw security advisories
- Built with bash, jq, and healthy paranoia

---

## License

MIT
