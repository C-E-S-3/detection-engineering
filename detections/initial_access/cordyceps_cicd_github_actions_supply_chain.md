# Cordyceps CI/CD GitHub Actions Supply Chain Hijack

**MITRE Techniques:** T1195.001, T1552.004, T1059.004

**Severity:** High

**Status:** Disclosed June 24, 2026; no widespread exploitation confirmed pre-disclosure

## Vulnerability

Systemic class of GitHub Actions misconfiguration (codenamed "Cordyceps" by Novee Security)
where workflows triggered by pull requests from forks are granted write scope or secret access.
Any unauthenticated user with a free GitHub account can exploit this to:

- Execute arbitrary code in a privileged CI context
- Steal GitHub App tokens, org secrets, and CI credentials
- Forge approvals or push unauthorized code to target repositories

300+ high-impact repos were found exploitable including Microsoft Azure Sentinel, Google ADK,
Apache Doris, Cloudflare Workers SDK, and Python Software Foundation repositories.

## Attack Vector

```
Unauthenticated attacker (free GitHub account)
  → Fork target repository
    → Open PR or post PR comment with crafted payload
      → pull_request_target workflow triggered with write/admin scope
        → Attacker code executes in privileged CI context
          → Steal GitHub App keys / org secrets
            → Push unauthorized code / forge approvals
              → Supply chain compromise downstream
```

## Detection Signals

| Signal | Source | Rule |
|--------|--------|------|
| External fork contributor triggers pull_request_target workflow | GitHub Audit Log | 103634 |
| Workflow with write token scope triggered by pull_request_target | GitHub Audit Log | 103635 |
| CI runner spawning credential exfiltration commands | Sysmon/Auditd | 103636 |
| Secret accessed by workflow triggered from outside collaborator | GitHub Audit Log | 103637 |
| Workflow YAML file modified in external contributor PR | GitHub Audit Log | 103638 |

## Log Source Requirements

- GitHub Enterprise audit log forwarding via webhook to Wazuh (custom decoder required)
- Sysmon/auditd on self-hosted GitHub Actions runners
- GitHub audit log events: `workflow_run`, `pull_request_target`, secret access events

## Immediate Mitigations

1. Audit all `.github/workflows/*.yml` for `pull_request_target` with `secrets:` context
2. Set explicit `permissions: read-all` on all workflows; grant write only where required
3. Use `pull_request` (restricted, not `pull_request_target`) for untrusted fork builds
4. Rotate any secrets/tokens accessible from workflows triggered by external PRs
5. Deploy `harden-runner` or equivalent to detect credential exfiltration at CI runtime

## References

- [Novee Security — Cordyceps](https://novee.security/blog/cordyceps/)
- [The Hacker News — Cordyceps Exposes 300+ Repos](https://thehackernews.com/2026/06/cordyceps-cicd-flaws-expose-300-github.html)
- [SecurityWeek — Exploitable CI/CD Vulnerabilities](https://www.securityweek.com/exploitable-ci-cd-vulnerabilities-expose-millions-of-repositories-to-hijacking/)
