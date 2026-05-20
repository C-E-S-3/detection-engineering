---
scraped_at: 2026-05-20T00:00:00Z
source_url: https://www.wiz.io/blog/durabletask-teampcp-supply-chain-attack
report_type: threat-intel
severity: critical
title: "TeamPCP Wave 3: durabletask PyPI Compromise and GitHub Internal Repository Breach"
---

## 1. IOCs

### Domains

| Domain | Description |
|--------|-------------|
| `filev2.getsession.org` | Session Protocol's open-group file upload API endpoint; TeamPCP abuses it to exfiltrate stolen credentials — selected deliberately because Session is a legitimate privacy messenger unlikely to be blocked at enterprise egress |
| `api.masscan.cloud` | Attacker-controlled server; malicious GitHub Actions workflows serialize repository secrets into a JSON blob and POST to this endpoint for collection |

### Malicious Package Versions

| Package | Ecosystem | Malicious Versions | Published (UTC) | Description |
|---------|-----------|-------------------|-----------------|-------------|
| `durabletask` | PyPI | 1.4.1, 1.4.2, 1.4.3 | 2026-05-19 16:19, 16:49, 16:54 | Official Microsoft Durable Task Python SDK trojanzied; all three versions published within 35 minutes; packages quarantined by PyPI following Wiz disclosure |

---

## 2. TTPs

| MITRE Tactic | Technique ID | Technique Name | Usage |
|---|---|---|---|
| Initial Access | T1195.002 | Supply Chain Compromise: Compromise Software Supply Chain | Three malicious durabletask versions uploaded directly to PyPI via `twine`; packages modified locally before publish |
| Initial Access | T1195.003 | Supply Chain Compromise: Compromise Hardware Supply Chain | Poisoned VS Code extension used to compromise GitHub employee device and exfiltrate internal repo credentials |
| Credential Access | T1552.007 | Unsecured Credentials: Container API | GitHub Actions OIDC tokens and repository secrets extracted; cloud credentials (AWS, Azure, GCP, Kubernetes) harvested by malicious durabletask dropper |
| Credential Access | T1555 | Credentials from Password Stores | Durabletask payload harvests credentials from 90+ developer tool configurations and password managers |
| Exfiltration | T1048.003 | Exfiltration Over Alternative Protocol: Exfiltration Over Unencrypted Non-C2 Protocol | Stolen credentials uploaded to `filev2.getsession.org` via Session Protocol's file transfer API |
| Exfiltration | T1567.002 | Exfiltration Over Web Service: Exfiltration to Cloud Storage | Repository secrets serialized as JSON and POSTed to `api.masscan.cloud` from compromised GitHub Actions runner |
| Persistence | T1554 | Compromise Host Software Binary | Self-propagating worm behavior: infected CI environments spread lateral compromise through cloud infrastructure |
| Impact | T1485 | Data Destruction | Claimed breach and attempted sale of ~3,800 GitHub internal repositories on criminal forum |

---

## 3. Malware & Tools

### durabletask Trojan (Wave 3)

The malicious versions of `durabletask` (1.4.1–1.4.3) contain a dropper injected into the package source files that executes a 28 KB payload silently upon package import. The payload:

- Steals credentials from AWS (`~/.aws/credentials`), Azure, GCP, Kubernetes (`~/.kube/config`), and 90+ developer tool configuration files
- Targets password managers for stored credentials
- Spreads laterally through cloud infrastructure using harvested credentials
- Exfiltrates all collected data to `api.masscan.cloud`

### GitHub VS Code Extension Implant

TeamPCP compromised a GitHub employee's device through a poisoned VS Code extension, enabling access to approximately 3,800 internal GitHub repositories. GitHub confirmed the attack vector on May 20, 2026, and:
- Rotated critical secrets on the day of detection
- Isolated the affected endpoint immediately
- Found no evidence of impact to customer information stored outside GitHub's internal infrastructure

### C2 Infrastructure Evolution

| Wave | IOCs | Campaign |
|------|------|----------|
| Wave 1 (March 2026) | `scan.aquasecurtiy[.]org`, `tdtqy-oyaaa-aaaae-af2dq-cai[.]raw[.]icp0[.]io` | Trivy Action GitHub Actions compromise |
| Wave 2 (May 11, 2026) | `git-tanstack[.]com`, `83.142.209[.]194`, `getsession.org` nodes | Mini Shai-Hulud: TanStack / Mistral AI / Guardrails AI |
| Wave 3 (May 19–20, 2026) | `filev2.getsession.org`, `api.masscan.cloud` | durabletask PyPI + GitHub internal breach |

---

## 4. Threat Actor / Campaign Attribution

| Attribute | Value |
|---|---|
| Actor | TeamPCP |
| Google TIG Tracking | UNC6780 |
| Campaign | Wave 3 of ongoing supply chain offensive; third major attack burst since March 2026 |
| Prior Campaigns | Trivy Action (March 2026), Telnyx PyPI (March 2026), Axios npm (March 2026), LiteLLM (March 2026), Mini Shai-Hulud/TanStack (May 11–12, 2026), node-ipc (May 2026) |
| New Victims | Microsoft (durabletask SDK), GitHub (internal repositories via VS Code extension) |
| Targeting | CI/CD ecosystems, PyPI packages, developer tooling, AI/ML infrastructure |
| Motivation | Financial — credential theft, ransomware partnership monetization, direct access sale |

---

## 5. Splunk Detection Searches

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Network_Traffic.All_Traffic
  where All_Traffic.dest_domain IN ("filev2.getsession.org","api.masscan.cloud")
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
  where Processes.process_name IN ("python3","python","pip","pip3")
    AND (Processes.process="*durabletask*")
  by Processes.dest Processes.user Processes.parent_process_name
     Processes.process_name Processes.process Processes.process_id
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=80
| table firstTime lastTime dest user parent_process_name process_name process risk_score
```

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Processes
  where Processes.process_name IN ("python3","python","node","pip")
    AND (Processes.process="*filev2.getsession.org*"
         OR Processes.process="*api.masscan.cloud*")
  by Processes.dest Processes.user Processes.parent_process_name Processes.process_name Processes.process
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=95
| table firstTime lastTime dest user process_name process risk_score
```

```spl
index=`github_audit_logs`
action="packages.publish"
| eval is_microsoft_pkg=if(match(package,"^durabletask"), 1, 0)
| where is_microsoft_pkg=1
| eval flag=if(match(actor,"(?i)bot|github-actions|runner"), "automated_publish_suspicious", "manual_publish_review")
| stats count by actor package version flag _time
| eval risk_score=case(flag="automated_publish_suspicious", 95, 1=1, 75)
| table _time actor package version flag risk_score
```

---

## 6. Executive Summary

On May 19, 2026, TeamPCP (tracked by Google TIG as UNC6780) published three malicious versions of Microsoft's official `durabletask` Python SDK to PyPI (v1.4.1, v1.4.2, v1.4.3), all within a 35-minute window, continuing their pattern of supply chain attacks targeting developer and AI infrastructure. The trojaned packages download and execute a 28 KB credential-harvesting payload on import, stealing credentials from AWS, Azure, GCP, Kubernetes, and 90+ developer tool configurations, then exfiltrating to `api.masscan.cloud`.

On May 20, TeamPCP claimed on a criminal forum to have breached approximately 3,800 GitHub internal repositories, later confirmed by GitHub to have originated from a poisoned VS Code extension on an employee's device. GitHub rotated critical credentials and isolated the affected endpoint; no customer repository impact was confirmed.

This third attack wave introduces new C2 infrastructure — `filev2.getsession.org` (Session Protocol's file API, deliberately chosen to evade egress filtering) and `api.masscan.cloud`. Organizations should block both domains at egress DNS, audit recent `durabletask` installations for versions 1.4.1–1.4.3, and rotate any CI/CD secrets from environments that executed these package versions. This attack represents an escalation by TeamPCP to directly targeting a major platform vendor (GitHub/Microsoft).
