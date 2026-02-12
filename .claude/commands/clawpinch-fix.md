---
description: Run ClawPinch scan and fix all findings
---

Run a ClawPinch security scan and remediate all findings.

Steps:
1. Locate ClawPinch — check for `clawpinch.sh` in the project or use `npx clawpinch`
2. Run `bash clawpinch.sh --json --no-interactive` to get findings as JSON
3. Parse findings and sort by severity (critical → warn → info)
4. For each finding:
   a. If `auto_fix` is present and non-empty, execute the command
   b. If no `auto_fix`, read the `evidence` and `remediation` fields, then apply the fix manually
   c. Verify the fix by checking that the evidence condition no longer exists
5. After all findings are addressed, re-run `bash clawpinch.sh --json --no-interactive`
6. Compare before/after counts and report what was fixed

Skip findings with severity "ok" — they require no action.
