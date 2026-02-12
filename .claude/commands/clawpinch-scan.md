---
description: Run a ClawPinch security audit
---

Run a ClawPinch security scan and summarize the results.

Steps:
1. Locate the ClawPinch installation by checking for `clawpinch.sh` in the current project or installed via npm
2. Run `bash clawpinch.sh --json --no-interactive` to get structured findings
3. Parse the JSON output — each item has: id, severity, title, description, evidence, remediation, auto_fix
4. Summarize results grouped by severity (critical first, then warn, info)
5. For each critical finding, highlight the evidence and remediation
6. Report total counts: N critical, N warning, N info, N ok

If ClawPinch is not found locally, run: `npx clawpinch --json --no-interactive`
