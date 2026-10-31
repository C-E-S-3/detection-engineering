---
scraped_at: 2026-10-31T00:00:00Z
source_url: https://www.bleepingcomputer.com/news/security/trojanized-claude-code-extension-in-cursor-marketplace-installs-ssh-backdoor/
report_type: threat-intel
severity: high
title: "Trojanized Claude Code Extension in Cursor Marketplace Installs SSH Backdoor (v2.1.313)"
---

# Trojanized Claude Code Extension in Cursor Marketplace Installs SSH Backdoor

**Date:** 2026-10-29 to 2026-10-30 (active window; removed from marketplace)
**Sources:** BleepingComputer, StepSecurity, Rescana, HelpNetSecurity, Cursor Blog
**Threat Type:** Supply chain / trojanized IDE extension
**Platform:** macOS (darwin-arm64), Windows (win32-x64)
**Attribution:** Unknown; no group attribution at time of writing

---

## Executive Summary

A malicious version of the Claude Code extension (v2.1.313) was published to the Cursor IDE marketplace on October 29, 2026 and remained available for approximately 11 hours before removal. The trojanized VSIX package contained a backdoor that appended an attacker-controlled SSH public key (labeled `svc-telemetry`) to the victim's `~/.ssh/authorized_keys` file and established a persistent reverse SSH tunnel to attacker infrastructure. Critically, **uninstalling the extension does not remove the backdoor**: the SSH key persists in `authorized_keys` and the attacker retains unauthorized remote access until the key is manually removed. Cursor confirmed the extension was not developed or authorized by Anthropic. Users who installed Claude Code for Cursor between approximately 14:00 UTC and 01:00 UTC on October 29–30, 2026 may be compromised regardless of whether they subsequently uninstalled the extension.

---

## 1. Indicators of Compromise (IOCs)

### File Hashes

| Hash | Type | Platform | Context |
|------|------|----------|---------|
| `fcbb327e38e61c4fec795e0d0591f52cd1014b813d20a5912104953c3a17c364` | SHA256 | macOS darwin-arm64 | Malicious Claude Code VSIX v2.1.313 |
| `3de1722901165769893bef57c72594e9a54459faa23f3091b136b79966edd081` | SHA256 | Windows win32-x64 | Malicious Claude Code VSIX v2.1.313 |

### Behavioral

- SSH public key with comment/label `svc-telemetry` appended to `~/.ssh/authorized_keys`
- Outbound TCP/22 or TCP/8099 connection from IDE process (cursor, its Extension Host worker, or spawned shell)
- HTTP POST to attacker's `/beacon` endpoint on port 8099
- Reverse SSH tunnel: `ssh -R` or equivalent, connecting outbound to maintain remote access

### Artifact Indicators

- Presence of SSH key comment `svc-telemetry` in `~/.ssh/authorized_keys`
- IDE Extension Host (cursor) spawning `ssh` process with `-R` flag

---

## 2. TTPs (MITRE ATT&CK Mapping)

| Tactic | Technique | Description |
|--------|-----------|-------------|
| Persistence (TA0003) | T1098.004 — Account Manipulation: SSH Authorized Keys | Appends attacker SSH public key labeled `svc-telemetry` to victim's authorized_keys |
| Persistence (TA0003) | T1572 — Protocol Tunneling | Reverse SSH tunnel maintains persistent attacker access even after extension removal |
| Command and Control (TA0011) | T1071.001 — Application Layer Protocol: Web Protocols | HTTP POST `/beacon` on port 8099 for C2 check-in |
| Initial Access (TA0001) | T1195.001 — Supply Chain Compromise: Compromise Software Dependencies | Trojanized VSIX published to Cursor marketplace; targets developer machines |
| Defense Evasion (TA0005) | T1036.005 — Masquerading: Match Legitimate Name or Location | Extension impersonates the legitimate Claude Code (claude.ai/code) by Anthropic |

---

## 3. Malware & Tools

**Trojanized Claude Code VSIX v2.1.313**

- Delivery: Cursor IDE marketplace (extension ID mirrors the legitimate Claude Code extension name)
- Backdoor behavior:
  - Appends SSH public key with comment `svc-telemetry` to `~/.ssh/authorized_keys`
  - Initiates reverse SSH tunnel for persistent attacker access
  - HTTP POST `/beacon` on port 8099 (C2 check-in / registration)
- Platforms confirmed: macOS darwin-arm64, Windows win32-x64
- Persistence survives extension uninstall: `authorized_keys` is not modified on uninstall
- Legitimate extension: Claude Code for Cursor is distributed by Anthropic; the legitimate VSIX does not modify SSH configuration

**Remediation for affected users:**

1. Remove the `svc-telemetry` key from `~/.ssh/authorized_keys` (or the equivalent Windows SSH config path)
2. Rotate any SSH keys that may have been accessible on the compromised host
3. Audit for any unauthorized SSH sessions during the exposure window (Oct 29 14:00 UTC – Oct 30 01:00 UTC)
4. Check for other persistence mechanisms (scheduled tasks, cron jobs) installed during the exposure window

---

## 4. Threat Actor / Campaign Attribution

No attribution to a known threat actor or group at time of writing. The targeting of developer machines via trojanized IDE extensions is consistent with patterns seen in DPRK Lazarus/Contagious Interview campaigns (who have previously targeted developers via npm packages, GitHub repositories, and fake job interviews), as well as financially motivated groups targeting cryptocurrency developers. However, no technical overlap with known groups has been confirmed in open-source reporting for this specific incident.

---

## 5. Splunk Detection Opportunities

### 5a. SSH authorized_keys Modification by IDE Process

```spl
index=* sourcetype IN ("WinEventLog:Security","XmlWinEventLog:Microsoft-Windows-Sysmon/Operational",
                        "linux_secure","macos_secure","osquery:results")
(EventCode=11 OR EventType="file_created" OR EventType="file_modified")
(TargetFilename="*authorized_keys*" OR file_path="*authorized_keys*")
| eval parent_image=coalesce(Image,process_path,"unknown")
| where match(parent_image,"(?i)(cursor|code|vscodium|extensionhost)")
| stats count by Computer host user parent_image TargetFilename file_path
| table Computer host user parent_image TargetFilename file_path count
```

### 5b. svc-telemetry Key Label in authorized_keys (Osquery / File Integrity)

```spl
index=* sourcetype="osquery:results" name="file_events"
(target_path="*authorized_keys*")
| rex field=md_content "svc-telemetry"
| stats count by hostIdentifier target_path
| table hostIdentifier target_path count
```

### 5c. Reverse SSH Tunnel from IDE Process

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Processes
  where Processes.process IN ("*ssh*-R*","*ssh*--reverse*")
  AND Processes.parent_process_name IN ("cursor","cursor-helper","cursor-ext","extensionhost","code","code-server")
  by Processes.dest Processes.user Processes.parent_process_name Processes.process_name Processes.process
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=90
| table firstTime lastTime dest user parent_process_name process_name process risk_score
```

### 5d. HTTP Beacon on Port 8099 from IDE

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Network_Traffic.All_Traffic
  where All_Traffic.dest_port=8099 All_Traffic.transport=tcp
  by All_Traffic.src All_Traffic.dest All_Traffic.app
| `drop_dm_object_name(All_Traffic)`
| where app IN ("cursor","cursor-helper","extensionhost","code","code-server")
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| table firstTime lastTime src dest app count
```

---

## 6. References

- [BleepingComputer — Trojanized Claude Code Extension in Cursor Marketplace Installs SSH Backdoor](https://www.bleepingcomputer.com/news/security/trojanized-claude-code-extension-in-cursor-marketplace-installs-ssh-backdoor/)
- [StepSecurity — Analysis of Malicious Claude Code VSIX v2.1.313](https://www.stepsecurity.io/blog/analysis-malicious-claude-code-vsix-cursor-marketplace)
- [Cursor Blog — Security Incident: Malicious Extension in Marketplace](https://cursor.sh/blog/security-incident-october-2026)
- [MITRE ATT&CK — T1098.004 Account Manipulation: SSH Authorized Keys](https://attack.mitre.org/techniques/T1098/004/)
- [MITRE ATT&CK — T1572 Protocol Tunneling](https://attack.mitre.org/techniques/T1572/)
- [MITRE ATT&CK — T1195.001 Supply Chain Compromise: Compromise Software Dependencies](https://attack.mitre.org/techniques/T1195/001/)
