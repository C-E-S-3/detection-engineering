---
scraped_at: 2026-06-24T12:00:00Z
source_url: https://novee.security/blog/cordyceps/
report_type: threat-intel
---

# Cordyceps: Systemic CI/CD Supply Chain Vulnerability in GitHub Actions

## Summary

Novee Security disclosed a critical class of CI/CD workflow misconfigurations on June 24, 2026,
codenamed "Cordyceps." The vulnerability allows any unauthenticated user with a free GitHub
account to forge approvals, push code, or steal repository secrets by triggering privileged
workflows via crafted pull requests or PR comments.

Over 300 high-impact GitHub repositories were found fully exploitable, including Microsoft Azure
Sentinel, Google AI Agent Development Kit, Apache Doris, Cloudflare Workers SDK, and Python
Software Foundation's Black formatter.

## Technical Details

**Root Cause:** Weak GitHub Actions workflow configurations where:
- `pull_request_target` events grant write repository scope to code from untrusted forks
- Workflow permissions are not explicitly scoped (default permissive settings)
- PR comments trigger workflow_dispatch without verifying commenter's trust level
- CI/CD secrets are accessible from workflow contexts triggered by external contributors

**Attack Flow:**
1. Attacker forks target repository (free account, no org membership required)
2. Attacker creates PR or posts crafted PR comment containing injection payload
3. GitHub Actions runs a privileged workflow triggered by the PR event
4. Attacker's code executes in the privileged CI context with write/admin scope
5. Attacker exfiltrates GitHub App tokens, org secrets, or non-expiring API keys

**Specific Examples:**
- Microsoft Azure Sentinel: PR comment could execute attacker code on Microsoft's CI
  and steal a non-expiring GitHub App key with write access to the repository
- Google AI Agent Development Kit: fork PR could execute on Google's CI to gain
  complete authority over a Google Cloud repository

## Scale

Novee scanned ~30,000 high-impact repositories and found 300+ fully exploitable.
No evidence of broad attacker abuse prior to coordinated disclosure; fixes received
from Microsoft, Google, Apache, Cloudflare, Python Software Foundation.

## MITRE ATT&CK Mapping

- **T1195.001** — Supply Chain Compromise: Software Supply Chain
- **T1552.004** — Unsecured Credentials: Private Keys (GitHub App token theft)
- **T1059.004** — Command and Scripting Interpreter: Unix Shell (workflow code exec)

## Detection

- GitHub audit log: `pull_request_target` workflow executions by outside collaborators
- GitHub audit log: secret access events triggered by fork contributor workflows
- GitHub audit log: `.github/workflows/*.yml` modifications in external contributor PRs
- CI runner: process spawning credential exfiltration patterns (`curl -H Authorization:`)

## Wazuh Rules

Rules 103634-103638 in `threat-intel-2026-06-24-netlogon-cordyceps-android-arista.xml`

## Recommended Mitigations

- Audit all `.github/workflows/` files for `pull_request_target` with `secrets` context
- Scope all workflow permissions explicitly (`permissions: read-all`)
- Require `pull_request` (not `pull_request_target`) for untrusted forks
- Use `harden-runner` or similar to detect CI secret exfiltration at runtime
- Rotate any CI secrets/tokens that may have been exposed

## References

- [The Hacker News — Cordyceps CI/CD Flaws](https://thehackernews.com/2026/06/cordyceps-cicd-flaws-expose-300-github.html)
- [Novee Security — Cordyceps Blog](https://novee.security/blog/cordyceps/)
- [SecurityWeek — CI/CD Vulnerabilities Expose Millions](https://www.securityweek.com/exploitable-ci-cd-vulnerabilities-expose-millions-of-repositories-to-hijacking/)
- [Dark Reading — Cordyceps Malicious Pull Requests](https://www.darkreading.com/application-security/cordyceps-malicious-pull-requests-developer-workflows)
