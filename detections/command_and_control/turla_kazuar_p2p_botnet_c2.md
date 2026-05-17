# Turla Kazuar P2P Botnet — C2 and Module Activity

## Description

Detects behavioral indicators of the Kazuar modular P2P botnet operated by Turla (Secret Blizzard / Russia FSB Center 16). Kazuar deploys three module types on every infected host — Kernel (leader election and task orchestration), Bridge (external C2 relay), and Worker (data collection) — and uses inter-process communication via named pipes and mailslots. The elected Kernel leader is the only node that communicates externally, reducing network telemetry; detection must therefore rely on host-based artifacts: PowerShell profile abuse for persistence, IPC mechanism artifacts (named pipes with MD5-hash-derived names, mailslots), AMSI/ETW bypass attempts, and anomalous Exchange Web Services (EWS) data flows. False positives: enterprise monitoring tools that use named pipes for IPC; PowerShell profiles legitimately modified by configuration management agents (establish a baseline and alert on deviations); EWS traffic from legitimate mail clients.

## MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| Tactic | Command and Control |
| Tactic ID | TA0011 |
| Technique | Multi-hop Proxy |
| Technique ID | T1090 |

Secondary techniques: T1071.001 (Application Layer Protocol: Web Protocols — HTTP/WSS C2), T1071.003 (Application Layer Protocol: Mail Protocols — EWS-based C2), T1008 (Fallback Channels — HTTP → WSS → EWS chain), T1547.013 (PowerShell Profile — persistence), T1562.001 (Impair Defenses: Disable or Modify Tools — AMSI/ETW bypass), T1056.001 (Keylogging — KEYL thread), T1113 (Screen Capture — PEEP thread), T1041 (Exfiltration Over C2 Channel — staged data via Bridge module)

## Lockheed Martin Kill Chain

| Phase |
|-------|
| Command & Control (C2) |

## Splunk Detection Query

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Filesystem
  where Filesystem.file_path IN ("*\\\\.\\\\mailslot\\\\*","*pipename-kernel*","*_hpbprndiLOC.dll*")
     OR Filesystem.file_name="_hpbprndiLOC.dll"
  by Filesystem.dest Filesystem.user Filesystem.process_name Filesystem.file_path Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    match(file_name,"(?i)_hpbprndiLOC"), 95,
    match(file_path,"(?i)pipename-kernel"), 85,
    match(file_path,"(?i)mailslot"), 75,
    1=1, 70)
| where risk_score >= 75
| table firstTime lastTime dest user process_name file_path file_name risk_score
```

**Supplemental: Kazuar PowerShell profile persistence**

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Processes
  where (Processes.process="*$profile*" OR Processes.process="*Microsoft.PowerShell_profile*"
     OR Processes.process="*profile.ps1*")
    AND Processes.process IN ("*New-Item*","*Set-Content*","*Add-Content*","*Out-File*","*echo*>*")
    AND NOT Processes.user IN (`approved_config_management_accounts`)
  by Processes.dest Processes.user Processes.parent_process_name Processes.process_name Processes.process
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=90
| table firstTime lastTime dest user parent_process_name process_name process risk_score
```

**Supplemental: Anomalous EWS data exfiltration (Bridge module)**

```spl
| tstats `security_content_summariesonly` sum(All_Traffic.bytes_out) as total_bytes_out
    count as connections min(_time) as firstTime max(_time) as lastTime
  from datamodel=Network_Traffic.All_Traffic
  where All_Traffic.dest_port IN (443,587,993,995)
    AND All_Traffic.app IN ("ews","exchange","https")
  by All_Traffic.src_ip All_Traffic.dest_ip All_Traffic.app
| `drop_dm_object_name(All_Traffic)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    app="ews" AND total_bytes_out > 52428800, 90,
    app="ews" AND total_bytes_out > 10485760, 80,
    connections > 200 AND total_bytes_out > 10485760, 75,
    1=1, 50)
| where risk_score >= 75
| table firstTime lastTime src_ip dest_ip app connections total_bytes_out risk_score
```

**Supplemental: Kazuar file hash match**

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Filesystem
  where Filesystem.file_hash IN (
    "69908f05b436bd97baae56296bf9b9e734486516f9bb9938c2b8752e152315d4",
    "c1f278f88275e07cc03bd390fe1cbeedd55933110c6fd16de4187f4c4aaf42b9",
    "6eb31006ca318a21eb619d008226f08e287f753aec9042269203290462eaa00d",
    "436cfce71290c2fc2f2c362541db68ced6847c66a73b55487e5e5c73b0636c85")
  by Filesystem.dest Filesystem.user Filesystem.file_path Filesystem.file_name Filesystem.file_hash
| `drop_dm_object_name(Filesystem)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=95
| table firstTime lastTime dest user file_path file_name file_hash risk_score
```

## Risk Score Logic

| Condition | Score | Rationale |
|-----------|-------|-----------|
| Known Kazuar file hash detected on disk | 95 | Direct IOC match; no legitimate software uses these hashes |
| Kazuar loader DLL name (`_hpbprndiLOC.dll`) present | 95 | Loader artifact is unique to Kazuar; no legitimate use case |
| Named pipe artifact matching `pipename-kernel-<version>` pattern | 85 | MD5-derived pipe names are distinctive to Kazuar IPC; rarely seen in legitimate software |
| PowerShell profile modification by non-CM account | 90 | Kazuar T1547.013 persistence mechanism; legitimate changes come only from authorized config management |
| EWS outbound > 50 MB from single host | 90 | Kazuar Bridge module exfiltration via Exchange; 50+ MB EWS in a session is anomalous for most endpoints |
| EWS outbound > 10 MB from single host | 80 | Moderate EWS exfiltration; review alongside other Kazuar indicators |

## Associated Threat Actors

| Actor | References |
|-------|-----------|
| Secret Blizzard (Turla / VENOMOUS BEAR / Uroburos / Snake) | [MITRE ATT&CK G0010](https://attack.mitre.org/groups/G0010/), [Microsoft — Kazuar Anatomy](https://www.microsoft.com/en-us/security/blog/2026/05/14/kazuar-anatomy-of-a-nation-state-botnet/), [CISA — Turla](https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-129a) |

## References

- [Microsoft Security Blog — Kazuar: Anatomy of a Nation-State Botnet (2026-05-14)](https://www.microsoft.com/en-us/security/blog/2026/05/14/kazuar-anatomy-of-a-nation-state-botnet/)
- [BleepingComputer — Russian Hackers Turn Kazuar Backdoor Into Modular P2P Botnet](https://www.bleepingcomputer.com/news/security/russian-hackers-turn-kazuar-backdoor-into-modular-p2p-botnet/)
- [MITRE ATT&CK — T1090 Proxy](https://attack.mitre.org/techniques/T1090/)
- [MITRE ATT&CK — T1547.013 PowerShell Profile](https://attack.mitre.org/techniques/T1547/013/)
- [MITRE ATT&CK — G0010 Turla](https://attack.mitre.org/groups/G0010/)
