# OpenClaw Threat Model

This document identifies the attack surfaces, threat actors, real-world
incidents, and mitigation strategies relevant to OpenClaw deployments.
ClawPinch checks map directly to the mitigations listed here.

---

## 1. Attack Surfaces

### 1.1 Gateway

The gateway is the central process that brokers communication between the
user interface, channels, and skills. It exposes:

- **WebSocket endpoint** for real-time interaction. If bound to `0.0.0.0`
  or left unauthenticated, any process on the network can connect.
- **HTTP control API** for skill management, config reload, and diagnostics.
  Debug endpoints may leak internal state.
- **Auth token handling.** CVE-2026-25253 demonstrated that the control UI
  can be tricked into sending the gateway auth token to an attacker-controlled
  WebSocket server via a malicious `gatewayUrl` query parameter.

**Relevant checks:** CHK-CFG-001, CHK-CFG-002, CHK-CFG-003, CHK-CFG-007,
CHK-CFG-009, CHK-NET-001, CHK-NET-002, CHK-NET-003, CHK-NET-005,
CHK-NET-007, CHK-CVE-002.

### 1.2 Channels

Channels connect the gateway to external services (Slack, Discord, web UIs,
etc.). Each channel:

- Receives untrusted user input and forwards it to the gateway.
- May invoke skills on behalf of the user, inheriting the channel's
  permission scope.
- Can be misconfigured to allow unauthenticated access or overly broad
  skill invocation.

**Relevant checks:** CHK-PRM-003, CHK-PRM-004, CHK-CFG-008, CHK-NET-006.

### 1.3 Skills

Skills are the primary extension point and the largest attack surface:

- **Filesystem access.** A skill that requests write access can modify
  configuration, plant persistence, or exfiltrate data.
- **Shell execution.** Skills that invoke shell commands are one step away
  from full system compromise. CVE-2026-24763 showed that the Docker sandbox
  could be escaped via PATH manipulation. CVE-2026-25157 showed OS command
  injection through an unescaped SSH project path.
- **Network access.** A skill with outbound network access can exfiltrate
  data or act as a tunnel.
- **Eval/exec patterns.** Skills that dynamically construct and execute code
  are trivially exploitable via prompt injection.
- **Cross-skill access.** A malicious skill that can invoke other skills may
  escalate its own privileges.

**Relevant checks:** CHK-SKL-001 through CHK-SKL-010, CHK-PRM-001,
CHK-PRM-002, CHK-PRM-004.

### 1.4 Cron / Scheduled Tasks

Cron jobs run skills on a timer without human oversight:

- Jobs that run as root combine maximum privilege with zero human review.
- Jobs without timeouts can hang indefinitely, holding resources.
- Rapid-fire schedules may be used to exfiltrate data in small increments
  or to brute-force internal services.
- Jobs with network access can phone home on a schedule.

**Relevant checks:** CHK-CRN-001 through CHK-CRN-006.

### 1.5 Supply Chain

Skills are installed from registries. The supply chain introduces:

- **Untrusted registries.** Skills from unofficial sources may be
  backdoored.
- **Hash mismatches.** A skill whose local hash does not match the registry
  hash may have been tampered with post-download.
- **Unsigned skills.** Without signature verification, there is no
  guarantee of provenance.
- **Transitive dependencies.** A skill that fetches code at runtime
  bypasses all install-time checks.
- **No lockfile.** Without a lockfile, skill versions may silently drift.

**Relevant checks:** CHK-SUP-001 through CHK-SUP-008.

### 1.6 Moltbook (ClawPinch internal note)

Moltbook is a real-world example of a compromised OpenClaw-adjacent tool.
It was distributed as a seemingly legitimate note-taking skill but contained
an obfuscated exfiltration payload that:

1. Collected shell history, SSH keys, and API tokens.
2. Sent them to an attacker-controlled endpoint encoded in DNS queries.
3. Persisted via a cron job that re-downloaded the payload on each boot.

Moltbook highlights why skills must be treated as untrusted code.

### 1.7 ClawHavoc (C2 Framework)

ClawHavoc is an open-source command-and-control framework designed to
exploit OpenClaw deployments. It abuses:

- Skill installation to deploy implants.
- Gateway WebSocket connections for C2 communication.
- Cron jobs for persistence.
- Prompt injection to manipulate agent behavior.

ClawHavoc demonstrates that the OpenClaw attack surface is actively
weaponised. Defenders must assume that attackers have tooling purpose-built
for this platform.

---

## 2. Threat Actors

| Actor              | Motivation          | Capability    | Typical Attack                          |
|--------------------|---------------------|---------------|-----------------------------------------|
| Opportunistic bots | Cryptocurrency, spam| Low           | Scan for exposed gateways on 0.0.0.0   |
| Credential scrapers| Resale, lateral move| Medium        | Harvest API keys from misconfigured envs|
| Prompt injectors   | Data exfiltration   | Medium        | Inject payloads via channel input       |
| ClawHavoc operators| Persistent access   | High          | Deploy C2 implants via skill supply chain|
| Nation-state       | Espionage, sabotage | Very high     | Targeted supply-chain compromise        |

---

## 3. Real-World Incidents

### CVE-2026-25253 -- 1-Click RCE via Auth Token Exfiltration

- **CVSS:** 8.8
- **Vector:** Cross-site WebSocket hijacking. The control UI trusted a
  `gatewayUrl` query parameter, allowing an attacker to redirect the
  WebSocket handshake to a malicious server and capture the auth token.
- **Impact:** Full gateway takeover. The attacker could install skills,
  read conversations, and execute arbitrary commands.
- **Fixed in:** OpenClaw 2026.1.29
- **ClawPinch check:** CHK-CVE-002

### CVE-2026-24763 -- Docker Sandbox Escape via PATH Injection

- **CVSS:** 8.8
- **Vector:** The skill sandbox constructed shell commands using the
  `PATH` environment variable without sanitisation. An attacker could set
  `PATH` to a directory containing a malicious binary named after a common
  utility.
- **Impact:** Escape from the Docker sandbox to the host.
- **Fixed in:** OpenClaw 2026.1.29
- **ClawPinch check:** CHK-CVE-003

### CVE-2026-25157 -- OS Command Injection via SSH Project Path

- **CVSS:** 8.8
- **Vector:** The `sshNodeCommand` error handler echoed the project root
  path into a shell command without escaping. A crafted project name
  achieved code execution.
- **Impact:** Remote code execution on the SSH host.
- **Fixed in:** OpenClaw 2026.1.29
- **ClawPinch check:** CHK-CVE-004

### Moltbook Breach

- **Date:** January 2026
- **Vector:** A popular note-taking skill on ClawHub was updated to
  include obfuscated data exfiltration. The update passed automated review
  because the payload was encoded as base64 within a seemingly benign
  string constant.
- **Impact:** Thousands of users had shell histories, SSH keys, and API
  tokens exfiltrated before the skill was pulled.
- **Lesson:** Supply-chain integrity checks and skill signature
  verification are essential. Trust cannot be based on popularity alone.

### ClawHub Compromise

- **Date:** January 2026
- **Vector:** Attackers gained access to a ClawHub maintainer account
  and published backdoored versions of several popular skills.
- **Impact:** Downstream users who updated without verifying hashes
  received compromised skills.
- **Lesson:** Hash verification (CHK-SUP-002), lockfiles (CHK-SUP-006),
  and certificate pinning (CHK-SUP-007) are all necessary layers.

---

## 4. Mitigation Strategies

Each mitigation maps to one or more ClawPinch checks.

| Mitigation                              | Checks                          |
|-----------------------------------------|---------------------------------|
| Bind gateway to 127.0.0.1              | CHK-CFG-001, CHK-NET-001       |
| Enable gateway authentication           | CHK-CFG-002, CHK-NET-002       |
| Enable TLS on all endpoints             | CHK-CFG-003, CHK-NET-003       |
| Disable debug mode in production        | CHK-CFG-004                     |
| Restrict config file permissions        | CHK-CFG-005                     |
| Rotate default credentials              | CHK-CFG-006                     |
| Restrict CORS origins                   | CHK-CFG-007                     |
| Set session timeouts < 24h              | CHK-CFG-008                     |
| Enable rate limiting                    | CHK-CFG-009                     |
| Enable audit logging                    | CHK-CFG-010, CHK-PRM-008       |
| Remove secrets from config files        | CHK-SEC-001 .. CHK-SEC-008     |
| Only install signed skills              | CHK-SKL-004, CHK-SUP-008       |
| Deny shell execution for skills         | CHK-SKL-003, CHK-SKL-008       |
| Apply least-privilege to permissions    | CHK-PRM-001 .. CHK-PRM-007     |
| Sandbox cron jobs                       | CHK-CRN-001 .. CHK-CRN-006    |
| Upgrade past known CVEs                 | CHK-CVE-001 .. CHK-CVE-005     |
| Verify supply-chain integrity           | CHK-SUP-001 .. CHK-SUP-008     |
| Use HTTPS for all registry connections  | CHK-SUP-003                     |
| Maintain a skill lockfile               | CHK-SUP-006                     |
| Pin registry TLS certificates           | CHK-SUP-007                     |
| Restrict outbound network from sandbox  | CHK-NET-008, CHK-CRN-006       |

---

## 5. Trust Boundaries

```
  ┌─────────────────────────────────────────────────────┐
  │                    Internet                          │
  │                                                     │
  │   ┌───────────┐          ┌──────────────┐          │
  │   │ Attacker  │          │  ClawHub     │          │
  │   │ / Bot     │          │  Registry    │          │
  │   └─────┬─────┘          └──────┬───────┘          │
  └─────────┼───────────────────────┼──────────────────┘
  ══════════╪═══════FIREWALL════════╪═══════════════════
  ┌─────────┼───────────────────────┼──────────────────┐
  │         ▼                       ▼                   │
  │   ┌───────────┐          ┌──────────────┐          │
  │   │  Gateway  │◄────────▶│   Skills     │          │
  │   │  :3000    │          │  (sandboxed) │          │
  │   └─────┬─────┘          └──────────────┘          │
  │         │                                           │
  │         ▼                                           │
  │   ┌───────────┐          ┌──────────────┐          │
  │   │ Channels  │          │  Cron Jobs   │          │
  │   │ (Slack,   │          │  (scheduled) │          │
  │   │  Discord) │          │              │          │
  │   └───────────┘          └──────────────┘          │
  │                                                     │
  │              Host Machine / Docker                  │
  └─────────────────────────────────────────────────────┘
```

Trust boundaries:
1. Internet <-> Gateway (must be protected by auth + TLS)
2. Gateway <-> Skills (skills are untrusted; sandbox must hold)
3. Gateway <-> Channels (channel input is untrusted)
4. Host <-> Registry (supply chain must be verified)
5. Cron <-> Skills (cron runs without human approval; extra caution needed)
