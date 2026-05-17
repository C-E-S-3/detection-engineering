---
scraped_at: 2026-05-17T00:00:00Z
source_url: https://www.wiz.io/blog/mini-shai-hulud-strikes-again-tanstack-more-npm-packages-compromised
report_type: threat-intel
severity: critical
title: "TeamPCP Mini Shai-Hulud: TanStack npm/PyPI Supply Chain Worm via GitHub Actions OIDC Theft"
---

## 1. IOCs

### Domains

| Domain | Description |
|--------|-------------|
| `git-tanstack[.]com` | Typosquatted domain operated by TeamPCP — PyPI payload delivery endpoint (`/transformers.pyz`) and C2 exfiltration |

### IP Addresses

| IP | Description |
|----|-------------|
| `83.142.209[.]194` | TeamPCP exfiltration C2 server — receives stolen OIDC tokens and npm credentials |

### Malicious Package Versions

| Package | Ecosystem | Malicious Version | Description |
|---------|-----------|-------------------|-------------|
| `@tanstack/*` (42 packages) | npm | Published 2026-05-11 19:20–19:26 UTC | Compromised via poisoned GitHub Actions pnpm store cache; 84 malicious artifacts |
| `guardrails-ai` | PyPI | `0.10.1` | Trojanized to download `transformers.pyz` from `git-tanstack[.]com` on import |
| `mistralai` | PyPI | `2.4.6` | Trojanized to download payload from `git-tanstack[.]com` on import |

---

## 2. TTPs

| MITRE Tactic | Technique ID | Technique Name | Usage |
|---|---|---|---|
| Initial Access | T1195.002 | Supply Chain Compromise: Compromise Software Supply Chain | Poisoned pnpm store cache injected via GitHub Actions pull_request_target workflow abuse; malicious npm/PyPI artifacts published to official registries |
| Initial Access | T1195.001 | Supply Chain Compromise: Compromise Software Dependencies and Development Tools | 42 npm packages under @tanstack namespace and 2 PyPI packages trojanized |
| Credential Access | T1552.007 | Unsecured Credentials: Container API | GitHub Actions OIDC tokens extracted from runner process memory; used to publish malicious package versions |
| Credential Access | T1552.001 | Unsecured Credentials: Credentials In Files | npm authentication tokens harvested from CI/CD runner environments |
| Exfiltration | T1567.001 | Exfiltration Over Web Service: Exfiltration to Code Repository | Stolen tokens dropped as Dune-themed GitHub repository dead drops for asynchronous retrieval |
| Exfiltration | T1048 | Exfiltration Over Alternative Protocol | Triple-channel C2: typosquatted domain, Session messenger network (getsession.org nodes), GitHub dead drops |
| Persistence | T1554 | Compromise Host Software Binary | Self-propagating worm that modifies newly installed package versions to contain the malicious payload |
| Impact | T1485 | Data Destruction | Dead-man's-switch daemon: if not periodically checked, triggers destructive wipe of developer home directories |
| Defense Evasion | T1027.002 | Obfuscated Files or Information: Software Packing | AES-256-CBC encrypted payload embedded in compiled JavaScript within npm extensions |
| Defense Evasion | T1497 | Virtualization/Sandbox Evasion | 15-minute execution delay before malicious payload activates |

---

## 3. Malware & Tools

### Mini Shai-Hulud Worm

"Mini Shai-Hulud" is TeamPCP's second-generation supply chain worm (following the original Shai-Hulud targeting Cisco's Trivy and related tooling in March 2026). The worm is self-propagating: once a developer installs a compromised package, the worm attempts to infect other npm packages in the same project's dependency tree.

**GitHub Actions Exploitation Chain**
1. Attacker forks `TanStack/router` repository
2. Opens a pull request that triggers a `pull_request_target` workflow (inheriting write permissions)
3. Malicious workflow run poisons the GitHub Actions pnpm store cache with attacker-controlled binaries
4. When a legitimate maintainer later triggers the release workflow, the poisoned cache is restored
5. Attacker-controlled binaries extract OIDC tokens directly from GitHub Actions runner process memory
6. Tokens used to publish 84 malicious npm artifacts across 42 `@tanstack` packages

**PyPI Payload**
The trojanized PyPI packages (`guardrails-ai 0.10.1`, `mistralai 2.4.6`) embed a Python dropper that, on import, fetches `transformers.pyz` from `https://git-tanstack[.]com/transformers.pyz` and executes it with `python3`.

**Triple-Channel C2**
- Primary: typosquatted domain `git-tanstack[.]com`
- Secondary: Session decentralized messenger (getsession.org seed nodes) for resilient async C2
- Dead drop: GitHub repositories with Dune-themed names used to store stolen credentials asynchronously

**Dead-Man's Switch**
A persistent daemon installed on compromised developer workstations monitors for periodic "check-in" signals. If the signal is absent for a configured period (e.g., after takedown), the daemon triggers destructive deletion of the developer's home directory.

---

## 4. Threat Actor / Campaign Attribution

| Attribute | Value |
|---|---|
| Actor | TeamPCP |
| Campaign | Mini Shai-Hulud (second supply chain worm; first was Shai-Hulud targeting Trivy Action in March 2026) |
| Prior Campaigns | Trivy Action GitHub Action compromise (March 2026), Telnyx PyPI backdoor (March 2026), Axios npm compromise (March 2026), LiteLLM supply chain attack |
| Targeting | Open-source software ecosystems (npm, PyPI); AI/ML tooling (Mistral AI, Guardrails AI, UiPath); developer workstations in CI/CD environments |
| Affected Organizations | TanStack, Mistral AI, Guardrails AI, UiPath, and 160+ additional packages; OpenAI reported two employee devices compromised |
| Infrastructure | Overlaps with ORB network infrastructure tracked across prior TeamPCP campaigns |

---

## 5. Splunk Detection Searches

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Network_Traffic.All_Traffic
  where All_Traffic.dest_ip="83.142.209.194"
     OR All_Traffic.dest_domain="git-tanstack.com"
  by All_Traffic.src_ip All_Traffic.dest_ip All_Traffic.dest_domain All_Traffic.dest_port
| `drop_dm_object_name(All_Traffic)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=95
| table firstTime lastTime src_ip dest_ip dest_domain dest_port risk_score
```

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Processes
  where (Processes.process="*git-tanstack*" OR Processes.process="*transformers.pyz*"
      OR Processes.process="*83.142.209.194*")
  by Processes.dest Processes.user Processes.parent_process_name Processes.process_name Processes.process
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=95
| table firstTime lastTime dest user parent_process_name process_name process risk_score
```

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Processes
  where Processes.process_name IN ("python3","python","node","npm")
    AND (Processes.process="*getsession.org*" OR Processes.process="*git-tanstack*"
         OR Processes.process="*transformers.pyz*")
  by Processes.dest Processes.user Processes.parent_process_name Processes.process_name Processes.process
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=90
| where risk_score >= 90
| table firstTime lastTime dest user process_name process risk_score
```

```spl
index=`github_audit_logs`
action IN ("workflows.run.completed","packages.publish")
| search repository="*tanstack*" OR package IN ("guardrails-ai","mistralai")
| eval flag=case(
    action="packages.publish" AND match(actor,"(?i)bot|action|github-actions"), "suspicious_automated_publish",
    action="workflows.run.completed" AND match(event,"cache_restore"), "cache_restore_event",
    1=1, "info")
| where flag != "info"
| stats count by actor repository action flag _time
| eval risk_score=case(flag="suspicious_automated_publish", 90, 1=1, 70)
| table _time actor repository action flag risk_score
```

---

## 6. Executive Summary

Between May 11–12, 2026, TeamPCP executed "Mini Shai-Hulud," a sophisticated supply chain worm attack against the TanStack JavaScript ecosystem, Mistral AI, Guardrails AI, and UiPath. The attack chain exploited a `pull_request_target` GitHub Actions workflow vulnerability to poison the CI/CD pnpm store cache, enabling extraction of OIDC tokens from runner process memory and publishing of 84 malicious npm artifacts across 42 `@tanstack` packages.

On PyPI, the trojanized `guardrails-ai 0.10.1` and `mistralai 2.4.6` packages fetch and execute a payload (`transformers.pyz`) from the typosquatted domain `git-tanstack[.]com` on import. Stolen credentials are exfiltrated via a triple-channel architecture: direct C2 at `83.142.209[.]194`, the Session decentralized messenger network, and GitHub repository dead drops. A persistent dead-man's-switch daemon threatens home directory destruction if not periodically disarmed.

This attack extends TeamPCP's documented pattern of CI/CD supply chain compromise (Trivy Action, Telnyx, LiteLLM, Axios from March 2026). Organizations using the compromised package versions should rotate all secrets accessible from affected CI/CD environments, audit GitHub Actions workflow permissions (especially `pull_request_target` with `write` permissions), and block outbound traffic to `git-tanstack[.]com` and `83.142.209[.]194`. Developers who installed affected packages between 2026-05-11 and 2026-05-12 should treat their workstations as compromised.
