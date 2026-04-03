# UNC5221 Ivanti Connect Secure Exploitation — SPAWN Ecosystem Implants (CVE-2025-22457)

## Description

Detects exploitation of CVE-2025-22457, a critical buffer overflow in Ivanti Connect Secure VPN appliances, as used by UNC5221 — a suspected China-nexus espionage group. Post-exploitation deploys the SPAWN malware ecosystem: TRAILBLAZE (in-memory dropper), BRUSHFIRE (passive SSL_read hook backdoor), SPAWNSNARE (kernel extractor), SPAWNWAVE (combined implant), and SPAWNSLOTH (log tampering). SPAWNSLOTH specifically targets the `dslogserver` process to suppress forensic evidence. Common false positives: legitimate Ivanti system files in `/bin/` and `/lib/`; process baseline deviations on VPN appliances should be investigated immediately given the sensitivity of these systems.

## MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| Tactic | Initial Access |
| Tactic ID | TA0001 |
| Technique | Exploit Public-Facing Application |
| Technique ID | T1190 |

Secondary techniques: T1070.004 (Indicator Removal — file/log deletion), T1014 (Rootkit — SSL_read hook), T1027 (Obfuscated Files — raw syscalls, in-memory execution)

## Lockheed Martin Kill Chain

| Phase |
|-------|
| Exploitation |

## Splunk Detection Query

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Filesystem
  where (Filesystem.file_path IN ("/tmp/.i", "/tmp/.r", "/bin/dsmain", "/lib/libdsupgrade.so", "/tmp/.liblogblock.so")
         OR Filesystem.action="created")
  by Filesystem.dest Filesystem.user Filesystem.file_path Filesystem.file_name Filesystem.action
| `drop_dm_object_name(Filesystem)`
| search file_path IN ("/tmp/.i", "/tmp/.r", "/bin/dsmain", "/lib/libdsupgrade.so", "/tmp/.liblogblock.so")
| eval risk_score=case(
    match(file_path, "/tmp/\.(i|r)$"), 95,
    match(file_path, "/tmp/\.liblogblock\.so"), 90,
    match(file_path, "/lib/libdsupgrade\.so"), 85,
    match(file_path, "/bin/dsmain"), 85,
    1=1, 70)
| where risk_score >= 70
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| table firstTime lastTime dest user file_path file_name action risk_score
```

**Supplemental: SPAWNSLOTH log tampering — dslogserver process injection**

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Processes
  where Processes.process_name="dslogserver"
    AND Processes.parent_process_name != "dscontrol"
  by Processes.dest Processes.user Processes.parent_process_name
     Processes.process_name Processes.process Processes.process_id
| `drop_dm_object_name(Processes)`
| eval risk_score=85
| where risk_score >= 70
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| table firstTime lastTime dest user parent_process_name process_name process risk_score
```

**Supplemental: Ivanti Connect Secure — anomalous file deletion in /tmp and core dumps**

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Filesystem
  where Filesystem.action="deleted"
    AND (Filesystem.file_path="/tmp/*" OR Filesystem.file_path="/data/var/cores/*")
  by Filesystem.dest Filesystem.user Filesystem.file_path Filesystem.action
| `drop_dm_object_name(Filesystem)`
| eval risk_score=case(
    match(file_path, "/data/var/cores/"), 80,
    match(file_path, "/tmp/\.(p|m|w|s|r|i)$"), 90,
    1=1, 60)
| where risk_score >= 60
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| table firstTime lastTime dest user file_path action risk_score
```

## Risk Score Logic

| Condition | Score | Rationale |
|-----------|-------|-----------|
| Known SPAWN implant paths (`/tmp/.i`, `/tmp/.r`) | 95 | Near-certain TP; hidden dotfile implants in /tmp are diagnostic of TRAILBLAZE/BRUSHFIRE |
| SPAWNSLOTH log tampering library (`/tmp/.liblogblock.so`) | 90 | Active forensic counter-measure; extremely suspicious on VPN appliances |
| SPAWNSNARE/SPAWNWAVE in system paths | 85 | System binary replacement indicates root-level compromise |
| dslogserver spawned by unexpected parent | 85 | Process injection to suppress logging; Ivanti-specific TTP |
| Core dump deletion or /tmp dotfile deletion | 60-90 | SPAWN cleanup pattern; correlate with other SPAWN indicators |

## Associated Threat Actors

| Actor | Relationship to Detection |
|-------|--------------------------|
| UNC5221 | Primary actor; China-nexus espionage group exploiting CVE-2025-22457 in Ivanti Connect Secure for global edge device targeting |
| UNC5221 (SPAWN ecosystem cluster) | Deploys TRAILBLAZE, BRUSHFIRE, SPAWNSNARE, SPAWNWAVE, SPAWNSLOTH post-exploitation |

## References

- [Google Threat Intelligence - China-Nexus Exploiting Critical Ivanti Vulnerability](https://cloud.google.com/blog/topics/threat-intelligence/china-nexus-exploiting-critical-ivanti-vulnerability)
- [MITRE ATT&CK - T1190 Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/)
- [CISA Advisory - CVE-2025-22457 Ivanti Connect Secure](https://www.cisa.gov/news-events/cybersecurity-advisories)
- [Ivanti Security Advisory - CVE-2025-22457](https://forums.ivanti.com/s/article/Security-Advisory-Ivanti-Connect-Secure-Policy-Secure-ZTA-Gateways)
