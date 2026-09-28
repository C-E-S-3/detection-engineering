---
scraped_at: 2026-09-28T06:00:00Z
source_url: https://securelist.com/macsync-new-version/121383/
report_type: threat-intel
severity: high
title: "MacSync macOS Infostealer: iCloud Calendar Dead-Drop C2 and Swift/ObjC Binary Payload Delivery"
---

# MacSync macOS Infostealer: iCloud Calendar Dead-Drop C2 and Swift/ObjC Binary Payload Delivery

## 1. IOCs

### Domains
| Indicator | Type | Context |
|-----------|------|---------|
| `toria[.]app` | Delivery Domain | Fake Toria cryptocurrency wallet website used to distribute MacSync-infected DMG; promoted via X and Telegram to crypto enthusiasts and developers |
| `caldav.icloud.com` | Abused Legitimate Service | Apple CalDAV endpoint abused as a dead-drop resolver; malware reads commands embedded in public iCloud calendar event DESCRIPTION fields |

### File Hashes (SHA256)
| Hash | Type | Context |
|------|------|---------|
| `b8b4b88205a8f594b95a841bc37342898f34cad8a5a9e4a22ce69a31a1208650` | SHA256 | MacSync backdoor component; C2 authentication token/session identifier observed in Kaspersky analysis; September 2026 variant |
| `ff3ab9ef841630364818396f62e696b72aed162cf0b895b6643ef25dad79b51d` | SHA256 | MacSync backdoor component; C2 authentication token/session identifier observed in Kaspersky analysis; September 2026 variant |

### Network Endpoints (Backdoor API)
| Endpoint | Context |
|----------|---------|
| `/v1/agent/ping` | MacSync backdoor heartbeat |
| `/v1/agent/refresh` | C2 token refresh |
| `/v1/asset/<id>/init` | Asset/payload initialization |
| `/v1/agent/<id>` | Agent-specific command endpoint |

## 2. TTPs

| Tactic | Technique ID | Technique | Usage |
|--------|-------------|-----------|-------|
| Initial Access | TA0001 | T1566 | Phishing — malicious DMG delivered via fake crypto wallet website, promoted on X and Telegram |
| Execution | TA0002 | T1059.004 | Command and Scripting Interpreter: Unix Shell — iCloud calendar DESCRIPTION piped to `zsh` to download and execute next stage |
| Execution | TA0002 | T1204.002 | User Execution: Malicious File — victim must mount and run DMG |
| Persistence | TA0003 | T1543.001 | Create or Modify System Process: Launch Agent — plist persistence for backdoor component |
| Defense Evasion | TA0005 | T1553 | Subvert Trust Controls — likely bypasses Gatekeeper via signing abuse (consistent with MaaS operations) |
| Credential Access | TA0006 | T1555.001 | Credentials from Password Stores: Keychain — exfiltrates macOS Keychain |
| Credential Access | TA0006 | T1539 | Steal Web Session Cookie — browser cookies and saved logins extracted |
| Collection | TA0009 | T1005 | Data from Local System — shell history, SSH keys, AWS credentials, Kubernetes configs, Git configs |
| Collection | TA0009 | T1081 | Credentials in Files — harvests AWS credential files, SSH private keys, `.kube/config` |
| Command and Control | TA0011 | T1102.001 | Web Service: Dead Drop Resolver — commands embedded in public iCloud calendar event DESCRIPTION fields, fetched via CalDAV protocol |
| Exfiltration | TA0010 | T1041 | Exfiltration Over C2 Channel — stolen data exfiltrated to attacker-controlled backend |

## 3. Malware & Tools

**MacSync** (also: MacSync Stealer, MacSync Backdoor)
- **Type:** macOS infostealer + persistent backdoor, sold as Malware-as-a-Service
- **First seen:** Earlier 2025; this is a new variant observed September 2026 with expanded capabilities
- **Language:** Swift and Objective-C (evolved from earlier AppleScript-based version)
- **Delivery:** Malicious DMG → multi-stage dropper chain → iCloud calendar polling → next-stage binary
- **C2 novelty:** Uses publicly readable iCloud Calendar events as a dead-drop; commands placed in the `DESCRIPTION` field of calendar events are fetched by the malware via CalDAV and piped directly to `zsh`. This abuses a legitimate Apple service and blends with expected macOS traffic.
- **Target data:** Browser credentials/cookies, Keychain database, Telegram data directory, cryptocurrency wallet files, shell history, SSH keys, AWS credentials, Kubernetes configs (`~/.kube/config`), Git config

## 4. Threat Actor / Campaign Attribution

Unknown financially motivated threat actor operating MacSync as a Malware-as-a-Service platform. Campaign identified by Kaspersky in September 2026. The "Toria" fake crypto wallet is one observed delivery vehicle; MaaS operators can substitute different lures.

Targets: macOS users — primarily cryptocurrency enthusiasts and software developers, given the credential targets (SSH, AWS, K8s, Git).

## 5. Splunk Detection Searches

### Detect zsh/sh Spawned with Pipe Input from Network Process
```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Processes
  where Processes.process_name IN ("zsh","sh","bash")
    AND Processes.parent_process_name IN ("curl","wget","python","python3","ruby","perl")
  by Processes.dest Processes.user Processes.parent_process_name
     Processes.process_name Processes.process Processes.process_id
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    match(parent_process_name,"(curl|wget)"), 85,
    1=1, 70)
| where risk_score >= 70
| table firstTime lastTime dest user parent_process_name process_name process risk_score
```

### Detect Access to macOS Keychain from Unexpected Processes
```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Filesystem
  where Filesystem.file_path IN ("*/Library/Keychains/*","*login.keychain*","*login.keychain-db*")
    AND NOT Filesystem.process_name IN ("security","securityd","ksfetch","keychain-interpose")
  by Filesystem.dest Filesystem.user Filesystem.process_name Filesystem.file_name Filesystem.file_path
| `drop_dm_object_name(Filesystem)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    match(file_path,"login.keychain"), 80,
    1=1, 60)
| where risk_score >= 60
| table firstTime lastTime dest user process_name file_name file_path risk_score
```

### Detect Network Connections to caldav.icloud.com from Non-Calendar Processes
```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Network_Traffic.All_Traffic
  where All_Traffic.dest_host="caldav.icloud.com"
    AND NOT All_Traffic.app IN ("Calendar","CalendarAgent","dataaccessd","accountsd")
  by All_Traffic.src All_Traffic.dest All_Traffic.dest_port All_Traffic.app All_Traffic.process
| `drop_dm_object_name(All_Traffic)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=90
| table firstTime lastTime src dest dest_port app process risk_score
```

### Detect LaunchAgent Plist Written by Non-System Process (macOS Persistence)
```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Filesystem
  where Filesystem.file_path IN ("*/Library/LaunchAgents/*.plist","*/Library/LaunchDaemons/*.plist")
    AND Filesystem.action="created"
    AND NOT Filesystem.user IN ("root","_","daemon")
  by Filesystem.dest Filesystem.user Filesystem.process_name Filesystem.file_name Filesystem.file_path
| `drop_dm_object_name(Filesystem)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=75
| where risk_score >= 75
| table firstTime lastTime dest user process_name file_name file_path risk_score
```

## 6. Executive Summary

Kaspersky published analysis in September 2026 of a new MacSync variant that introduces a novel command-and-control technique: embedding malicious commands in the DESCRIPTION field of publicly readable iCloud Calendar events, then piping the content to `zsh`. This dead-drop approach abuses a legitimate Apple service (`caldav.icloud.com`) and is difficult to block at the network level without disrupting genuine macOS Calendar synchronization. The malware is distributed as a trojanized DMG masquerading as a cryptocurrency wallet called "Toria," advertised on X and Telegram. MacSync steals browser credentials, Keychain data, Telegram sessions, SSH keys, AWS/Kubernetes/Git configs, and shell history. Two SHA256 hashes associated with the backdoor C2 authentication mechanism have been published. The distribution domain `toria[.]app` should be blocked at DNS/proxy. macOS endpoint agents should alert on unusual access to Keychain files and on LaunchAgent plist creation by non-system processes.

## References

- [Kaspersky Securelist: MacSync new version analysis](https://securelist.com/macsync-new-version/121383/)
- [BleepingComputer: MacSync malware uses public iCloud calendars to deliver new payloads](https://www.bleepingcomputer.com/news/security/macsync-malware-uses-public-icloud-calendars-to-deliver-new-payloads/)
- [Help Net Security: MacSync info-stealing malware hides malicious commands in an iCloud calendar](https://www.helpnetsecurity.com/2026/09/25/macsync-info-stealing-malware-for-macos/)
- [MITRE ATT&CK T1102.001: Dead Drop Resolver](https://attack.mitre.org/techniques/T1102/001/)
- [MITRE ATT&CK T1555.001: Keychain](https://attack.mitre.org/techniques/T1555/001/)
