---
scraped_at: 2026-11-12T00:00:00Z
source_url: https://blog.talosintelligence.com/china-nexus-uat-11587-targets-government-and-policy-organizations-across-asia-with-antino-backdoor/
report_type: threat-intel
severity: high
title: "UAT-11587 (China-nexus) Deploys Antino Backdoor Against Asian Government and Policy Organizations via Email Draft Dead-Drop C2"
---

## 1. IOCs

### Domains
| Indicator | Type | Context |
|-----------|------|---------|
| d32tpl7xt7175h.cloudfront[.]net | CloudFront domain | UAT-11587 Antino payload staging — low-confidence overlap with prior UNC6384 attribution per Arctic Wolf; Talos treats as UAT-11587 infrastructure |

### Hashes
No confirmed hashes available from secondary sources. Full SHA256 IOC list published in the Talos primary report.

### C2 Protocol Indicators
| Indicator | Context |
|-----------|---------|
| graph.microsoft.com | Microsoft Graph API endpoint abused for email-draft dead-drop C2 |
| onedrive.live.com / SharePoint tenant endpoints | OneDrive dead-drop alternative C2 channel |

## 2. TTPs

### MITRE ATT&CK

| Tactic | Technique | ID | Usage |
|--------|-----------|-----|-------|
| Initial Access | Spearphishing Attachment | T1566.001 | Targeted spear-phishing emails with HTA file attachments delivering the initial dropper |
| Execution | User Execution: Malicious File | T1204.002 | Victim opens HTA attachment, triggering execution of the Antino dropper chain |
| Command and Control | Web Service: Bidirectional Communication | T1102.002 | Antino Rust backdoor polls a victim-registered Microsoft 365 Outlook mailbox folder every 10 seconds for operator commands written as email drafts; responses written to draft folder |
| Command and Control | Web Service: One-Way Communication | T1102.001 | OneDrive dead-drop channel used as an alternate C2 for file staging and command delivery |
| Exfiltration | Exfiltration to Cloud Storage | T1567.002 | Collected data uploaded to attacker-controlled cloud storage via Graph API |
| Resource Development | Stage Capabilities: Upload Tool | T1608.001 | Payloads staged on Cloudflare R2 and Amazon CloudFront CDN infrastructure |
| Defense Evasion | Masquerading | T1036 | Backdoor communications blend into legitimate Microsoft 365 OAuth traffic on port 443 |

### Execution Chain
1. Spear-phishing email → HTA attachment
2. HTA executes dropper, downloads Antino Rust backdoor from CloudFront/Cloudflare R2 staging
3. Antino authenticates to Microsoft 365 via OAuth/Graph API using harvested or planted credentials
4. Antino polls Outlook draft folder (10-second interval) for operator commands
5. Collected data exfiltrated via OneDrive or Graph API calls

## 3. Malware & Tools

| Name | Type | Notes |
|------|------|-------|
| Antino | Rust backdoor | Implant using Microsoft Graph API (email drafts and OneDrive) for dead-drop C2; targets Windows environments; Gen 1 and Gen 2 variants identified by Talos |
| Falcon C2 / XG | Browser-based JS C2 framework | Related infrastructure; see separate report 2026-11-11_unit42-paloaltonetworks-com-falcon-c2-xg-browser-javascript-c2.md |

## 4. Threat Actor / Campaign Attribution

| Attribute | Detail |
|-----------|--------|
| Cluster | UAT-11587 |
| Nexus | China-nexus (high confidence per Talos) |
| Overlap | Low-confidence overlap with Jewelbug noted but not confirmed |
| Targets | Government, defense, diplomatic, policy, academic, and civil-society organizations across Asia |
| Countries | Taiwan, India, Philippines, Cambodia, Pakistan, Thailand, Myanmar (at least 8 countries total) |
| Active | September 2025 – at least July 2026; campaign may be ongoing |
| Scale | 10 confirmed + 5 probable affected institutional environments (Talos); secondary sources claim larger figures |
| Goal | Espionage / intelligence collection |

## 5. Splunk Detection Searches

### Email Draft Dead-Drop C2 via Microsoft Graph API

```spl
`sysmon`
(EventCode=3 OR EventCode=22)
dest_ip_port="graph.microsoft.com:443"
NOT (process_name IN ("outlook.exe","teams.exe","OneDrive.exe","msedge.exe",
                       "chrome.exe","firefox.exe","msedgewebview2.exe",
                       "SearchIndexer.exe","lsass.exe"))
| stats count min(_time) as firstTime max(_time) as lastTime by host user process_name process_id dest_hostname
| where count >= 5
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(count >= 50, 80, count >= 10, 65, 1=1, 50)
| where risk_score >= 50
| table firstTime lastTime host user process_name process_id dest_hostname count risk_score
```

> Detects non-email-client processes making repeated outbound HTTPS connections to `graph.microsoft.com`, indicating potential email-draft dead-drop C2. Legitimate false positive sources: custom LOB apps using Graph API (allowlist those process names).

### HTA Dropper Execution (Initial Access)

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Endpoint.Processes
where Processes.process_name="mshta.exe" Processes.process="*.hta*"
by Processes.dest Processes.user Processes.parent_process_name
   Processes.process_name Processes.process Processes.process_id
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    match(parent_process_name,"(outlook|thunderbird|winmail|explorer)\.exe"), 85,
    1=1, 65)
| where risk_score >= 65
| table firstTime lastTime dest user parent_process_name process_name process risk_score
```

> Detects mshta.exe invocations with HTA file arguments, particularly when spawned by email clients (Outlook). UAT-11587 initial delivery mechanism.

### CloudFront Payload Staging (IOC-Based)

```spl
`sysmon` EventCode=22
QueryName="d32tpl7xt7175h.cloudfront.net"
| stats count min(_time) as firstTime max(_time) as lastTime by host user QueryName
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=90
| table firstTime lastTime host user QueryName risk_score
```

> Specific IOC-based detection for UAT-11587 staging domain (low-confidence prior overlap with UNC6384). Any match warrants immediate investigation.

## 6. Executive Summary

Cisco Talos published (November 10–11, 2026) a detailed investigation of UAT-11587, a China-nexus cyber espionage cluster targeting government, defense, diplomatic, and academic organizations across at least 8 Asian countries since September 2025. The group delivers a Rust-based backdoor called **Antino** via spear-phishing with HTA attachments. 

The defining characteristic of this campaign is its use of **Microsoft 365 email draft folders as a dead-drop C2 channel** — Antino authenticates to victims' Microsoft 365 tenants via the Graph API and polls a designated Outlook folder every 10 seconds for operator-written command drafts, blending malicious communications into legitimate cloud service traffic. OneDrive serves as an alternative dead-drop and exfiltration channel.

Payloads are staged via Cloudflare R2 and Amazon CloudFront CDN infrastructure. Talos notes low-confidence infrastructure overlap with the separately tracked UNC6384 cluster, but treats UAT-11587 as a distinct set. The campaign aligns with strategic Chinese intelligence-collection priorities against Southeast and South Asian governments and policy organizations.

**Recommended actions:** Audit Microsoft 365 OAuth application consents; monitor Graph API access from non-standard processes; ensure Conditional Access policies block unrecognized device registrations; patch HTA-related execution vectors.
