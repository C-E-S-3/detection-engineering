---
scraped_at: "2026-11-15T00:00:00Z"
source_url: "https://www.bleepingcomputer.com/news/security/fireworks-ai-breach-led-to-malicious-cursor-claude-code-extension/"
report_type: threat-intel
severity: medium
title: "Fireworks AI Breach Leads to Malicious Claude Code Extension Versions 2.1.312 and 2.1.313 on VS Code Marketplace"
---

# Fireworks AI Breach Leads to Malicious Claude Code Extension Versions 2.1.312 and 2.1.313 on VS Code Marketplace

## 1. IOCs

| Type | Indicator | Confidence | Notes |
|------|-----------|------------|-------|
| Software version | Claude Code extension 2.1.312 | High | Malicious VS Code marketplace build; published Oct 29, 2026 |
| Software version | Claude Code extension 2.1.313 | High | Malicious VS Code marketplace build; published Oct 29, 2026 |
| Artifact | VS Code extension ID: `anthropic.claude-code` versions 2.1.312 and 2.1.313 | High | Only these two specific versions are known malicious; prior and subsequent versions are clean |

## 2. TTPs

| Tactic | Technique | ID | Description |
|--------|-----------|-----|-------------|
| Initial Access | Supply Chain Compromise: Software Supply Chain | T1195.002 | Attacker used an exposed Fireworks AI access key to access Cursor/AI coding agent trace data, extracted pipeline credentials, then published malicious extension versions 2.1.312 and 2.1.313 to the VS Code Marketplace under the legitimate `anthropic.claude-code` publisher ID |
| Execution | User Execution: Malicious File | T1204.002 | Malicious extension executes automatically when VS Code loads it; no user interaction required beyond having the extension installed and updating to the trojanized version |
| Persistence | Server Software Component: SSH | T1505.004 | Payload installs an SSH backdoor on the developer workstation; adds actor-controlled public key to the user's SSH authorized_keys |
| Discovery | System Information Discovery | T1082 | Payload enumerates hostname, username, OS version, installed tools, and git repository metadata for victim profiling |
| Discovery | File and Directory Discovery | T1083 | Enumerates files in common developer directories (workspace, home, config paths) to identify high-value targets (source code, credentials, .env files) |
| Exfiltration | Exfiltration Over C2 Channel | T1041 | Host and user enumeration data exfiltrated to attacker C2 prior to SSH backdoor installation |

## 3. Malware & Tools

| Name | Type | Description |
|------|------|-------------|
| Trojanized Claude Code extension 2.1.312/2.1.313 | Malicious VS Code extension | Legitimate extension with an injected payload; payload installs SSH backdoor and performs host/user enumeration |
| SSH backdoor | Persistence implant | Standard OpenSSH authorized_keys modification; actor public key appended to allow persistent access to developer workstations |

## 4. Attribution

| Actor | Confidence | Notes |
|-------|------------|-------|
| Unknown | Low | No attribution established as of Nov 14, 2026; Fireworks AI breach being investigated. Access suggests financially or espionage-motivated actor interested in developer workstations and source code. |

**Incident timeline:**
- **Pre-Oct 29, 2026**: Attacker compromises Fireworks AI via exposed access key; gains access to Cursor coding-agent execution traces containing pipeline credentials
- **Oct 29, 2026**: Malicious extension versions 2.1.312 and 2.1.313 published to VS Code Marketplace under legitimate `anthropic.claude-code` publisher
- **Oct 29, 2026**: Approximately 11-hour exposure window before the malicious versions were detected and removed
- **Nov 14, 2026**: BleepingComputer discloses the incident; Anthropic and Cursor publish advisories
- **Estimated exposure**: Up to 5,000 users who had the extension set to auto-update may have received the malicious versions during the 11-hour window

## 5. Splunk Detection Searches

### Developer workstation SSH authorized_keys modification by IDE process

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Filesystem
  where Filesystem.file_path="*/.ssh/authorized_keys" OR Filesystem.file_path="*\\.ssh\\authorized_keys"
  by Filesystem.dest Filesystem.user Filesystem.file_path Filesystem.process_name Filesystem.process_id
| `drop_dm_object_name(Filesystem)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    match(process_name, "code|code-server|cursor|windsurf|node"), 95,
    1=1, 75)
| where risk_score >= 75
| table firstTime lastTime dest user file_path process_name process_id risk_score
```

### VS Code extension process spawning network connections to unexpected external hosts

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Network_Traffic.All_Traffic
  where All_Traffic.app="code" OR All_Traffic.process_name="code" OR All_Traffic.process_name="cursor"
  AND NOT (All_Traffic.dest_host IN ("marketplace.visualstudio.com","update.code.visualstudio.com",
           "vscode.blob.core.windows.net","anthropic.com","api.anthropic.com","claude.ai"))
  by All_Traffic.src All_Traffic.dest_host All_Traffic.dest_port All_Traffic.process_name All_Traffic.user
| `drop_dm_object_name(All_Traffic)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=80
| table firstTime lastTime src dest_host dest_port process_name user risk_score
```

### Outbound SSH connections from workstations with active VS Code sessions

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Network_Traffic.All_Traffic
  where All_Traffic.dest_port=22 AND All_Traffic.direction="outbound"
  by All_Traffic.src All_Traffic.dest All_Traffic.dest_port All_Traffic.user
| `drop_dm_object_name(All_Traffic)`
| join type=inner src [
    | tstats `security_content_summariesonly` count
      from datamodel=Endpoint.Processes
      where Processes.process_name="code" OR Processes.process_name="cursor"
      by Processes.dest
    | rename dest as src ]
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=65
| table firstTime lastTime src dest dest_port user risk_score
```

## 6. Executive Summary

On October 29, 2026, an attacker who had previously breached Fireworks AI via an exposed API key used extracted credentials from Cursor coding-agent execution traces to publish malicious versions 2.1.312 and 2.1.313 of the Claude Code VS Code extension to the Visual Studio Code Marketplace. The malicious extensions were live for approximately 11 hours before removal, potentially reaching up to 5,000 users who had auto-update enabled. The injected payload installed an SSH backdoor (via authorized_keys modification) and performed host and user enumeration for victim profiling. The incident underscores two systemic risks: (1) AI coding-agent execution traces may contain sensitive credentials that must be treated as secrets, and (2) auto-updating IDE extensions from the VS Code Marketplace present a supply chain risk. Organizations should verify no systems have Claude Code extension versions 2.1.312 or 2.1.313 installed, audit SSH authorized_keys on developer workstations for unexpected entries, and enforce extension allowlists or pin approved versions. The SSH backdoor technique is consistent with previously documented IDE extension supply chain attacks.

## References

- [BleepingComputer - Fireworks AI Breach Led to Malicious Cursor Claude Code Extension](https://www.bleepingcomputer.com/news/security/fireworks-ai-breach-led-to-malicious-cursor-claude-code-extension/)
- [Anthropic Security Advisory - Claude Code Extension Compromise Oct 29 2026](https://www.anthropic.com/security-advisories/)
- [MITRE ATT&CK - T1195.002 Supply Chain Compromise: Software Supply Chain](https://attack.mitre.org/techniques/T1195/002/)
- [MITRE ATT&CK - T1505.004 Server Software Component: SSH](https://attack.mitre.org/techniques/T1505/004/)
- [VS Code Extension Security Best Practices](https://code.visualstudio.com/api/references/extension-guidelines)
