# GoSerpent ThumbcacheService File Collection Artifact

## Description

Detects the GoSerpent espionage toolset's ThumbcacheService DLL module, which collects files of interest from victim hosts and archives them to a distinctive staging path: `C:\Users\Public\thumbcache_605a.db`. This password-protected archive is a high-specificity forensic indicator for GoSerpent intrusions targeting Southeast Asian government, diplomatic, and intelligence organizations.

The actor also deploys Mimikatz and QuarksDumpLocalHash for credential access, and routes C2 through Stowaway SOCKS5 tunnels on compromised hosts. The overall toolset (GoSerpent RAT + McMx proxy + ThumbcacheService collector + Stowaway + TmcLoader) has been active since 2021.

False positive sources: extremely unlikely — the filename `thumbcache_605a.db` has no known legitimate use case; this staging path is highly specific to GoSerpent. Any detection should be treated as high confidence.

## MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| Tactic | Collection (TA0009) |
| Technique | T1560 — Archive Collected Data |
| Sub-technique | T1560.001 — Archive via Utility |
| Additional Tactic | Lateral Movement (TA0008), Credential Access (TA0006) |
| Additional Techniques | T1090 — Proxy (Stowaway SOCKS5), T1003 — OS Credential Dumping (Mimikatz / QuarksDumpLocalHash) |

## Lockheed Martin Kill Chain Phase

Actions on Objectives

## Splunk SPL Query

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Filesystem
  where Filesystem.file_path="*\\Users\\Public\\thumbcache_605a.db"
     OR Filesystem.file_name="thumbcache_605a.db"
  by Filesystem.dest Filesystem.user Filesystem.file_path Filesystem.file_name
     Filesystem.process_name Filesystem.action
| `drop_dm_object_name(Filesystem)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=95
| table firstTime lastTime dest user file_path file_name process_name action risk_score
```

**Companion: Mimikatz / QuarksDumpLocalHash execution (GoSerpent credential dumping stage):**

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Processes
  where (Processes.process_name IN ("mimikatz.exe", "QuarksDumpLocalHash.exe")
      OR Processes.process IN ("*sekurlsa::logonpasswords*", "*lsadump::sam*", "*privilege::debug*"))
  by Processes.dest Processes.user Processes.parent_process_name
     Processes.process_name Processes.process Processes.process_id
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=90
| table firstTime lastTime dest user parent_process_name process_name process risk_score
```

**Companion: Stowaway SOCKS5 proxy inbound connection detection (GoSerpent C2 routing stage):**

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Network_Traffic.All_Traffic
  where All_Traffic.transport="tcp"
    AND All_Traffic.direction="inbound"
    AND All_Traffic.dest_port > 1024
    AND All_Traffic.dest_port != 3389
    AND All_Traffic.dest_port != 443
    AND All_Traffic.dest_port != 80
  by All_Traffic.src All_Traffic.dest All_Traffic.dest_port
| `drop_dm_object_name(All_Traffic)`
| join dest
    [ | tstats `security_content_summariesonly` count
        from datamodel=Endpoint.Filesystem
        where Filesystem.file_path="*\\Users\\Public\\thumbcache_605a.db"
        by Filesystem.dest
      | `drop_dm_object_name(Filesystem)` ]
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=85
| table firstTime lastTime dest src dest_port risk_score
```

## Risk Score Logic

| Score | Condition |
|-------|-----------|
| 95 | File `thumbcache_605a.db` created in `C:\Users\Public\` — highly specific GoSerpent IOC |
| 90 | Mimikatz or QuarksDumpLocalHash execution (credential dump phase) |
| 85 | Inbound SOCKS5-like connection to host already showing GoSerpent filesystem artifact |

## Associated Threat Actors

- **Unnamed China-nexus espionage actor** — responsible for the GoSerpent toolset; active since 2021; targets Southeast Asian government agencies, diplomatic missions, and intelligence organizations; infrastructure hosted on Alibaba Cloud and UCLOUD HK; uses Stowaway (open-source, widely used by China-nexus groups) for SOCKS5 tunneling

## References

- Kaspersky Securelist (2026-07-17): https://securelist.com/goserpent-backdoor-in-southeast-asia/120687/
- MITRE ATT&CK T1560 — Archive Collected Data: https://attack.mitre.org/techniques/T1560/
- MITRE ATT&CK T1090 — Proxy: https://attack.mitre.org/techniques/T1090/
- MITRE ATT&CK T1003 — OS Credential Dumping: https://attack.mitre.org/techniques/T1003/
