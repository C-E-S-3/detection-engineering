---
scraped_at: 2026-09-28T12:00:00Z
source_url: https://raw.githubusercontent.com/PaloAltoNetworks/Unit42-timely-threat-intel/main/2026-09-28-AgtaBackup-RAT-Campaign.txt
report_type: threat-intel
severity: high
title: "AgtaBackup RAT Campaign: Fake Backup/RMM Software Delivering Custom C2 Agent with Credential Harvesting"
---

# AgtaBackup RAT Campaign: Fake Backup/RMM Software Delivering Custom C2 Agent with Credential Harvesting

## 1. IOCs

### C2 and Delivery Domains
| Indicator | Type | Context |
|-----------|------|---------|
| `avanade[.]cc` | C2 | AgtaBackup RAT C2 infrastructure |
| `backupplanetwealthagta[.]top` | C2 | AgtaBackup RAT C2 domain |
| `beehstwithust[.]org` | C2 | AgtaBackup RAT C2 domain |
| `blessingsbe[.]top` | C2 | AgtaBackup RAT C2 domain |
| `bootbackup[.]com` | Delivery | AgtaBackup fake backup software delivery |
| `bootprivate[.]com` | Delivery | AgtaBackup delivery domain |
| `cashyejrudga[.]live` | C2 | AgtaBackup RAT C2 domain |
| `childofwhho[.]top` | C2 | AgtaBackup RAT C2 domain |
| `connectprivae[.]top` | C2 | AgtaBackup RAT C2 domain |
| `criopifileeworking[.]top` | C2 | AgtaBackup RAT C2 domain |
| `datavaseffhjurd[.]top` | C2 | AgtaBackup RAT C2 domain |
| `electomm[.]sbs` | C2 | AgtaBackup RAT C2 domain |
| `emef[.]info` | C2 | AgtaBackup RAT C2 domain |
| `emsafetoproceedtaward[.]top` | C2 | AgtaBackup RAT C2 domain |
| `evobasin[.]info` | C2 | AgtaBackup RAT C2 domain |
| `ghxstworkingagent[.]top` | C2 | AgtaBackup RAT C2 domain |
| `greateshystfqsh[.]one` | C2 | AgtaBackup RAT C2 domain |
| `gsop[.]top` | C2 | AgtaBackup RAT C2 domain |
| `hr4hire[.]top` | C2 | AgtaBackup RAT C2 domain |
| `installapp[.]cc` | Delivery | AgtaBackup distribution domain |
| `jokermav[.]online` | C2 | AgtaBackup RAT C2 domain |
| `kresyuhjance[.]help` | C2 | AgtaBackup RAT C2 domain |
| `llgoldassociates[.]com` | C2 | AgtaBackup RAT C2 domain |
| `magicislanding[.]lol` | C2 | AgtaBackup RAT C2 domain |
| `outfitstryon[.]info` | C2 | AgtaBackup RAT C2 domain |
| `palnetworkingleup[.]top` | C2 | AgtaBackup RAT C2 domain |
| `piejaholoop[.]org` | C2 | AgtaBackup RAT C2 domain |
| `planetbizzingupcleananddirt[.]top` | C2 | AgtaBackup RAT C2 domain |
| `planetvocalfortesttheteas[.]cyou` | C2 | AgtaBackup RAT C2 domain |
| `planetvocalfortheteas[.]cyou` | C2 | AgtaBackup RAT C2 domain |
| `planetwealthonlycleancoffe[.]top` | C2 | AgtaBackup RAT C2 domain |
| `planetwealthonlycleantea[.]top` | C2 | AgtaBackup RAT C2 domain |
| `planetworkingclassrewor[.]top` | C2 | AgtaBackup RAT C2 domain |
| `planetworkingfortwo[.]top` | C2 | AgtaBackup RAT C2 domain |
| `planetwrokingclassforagemt[.]top` | C2 | AgtaBackup RAT C2 domain |
| `plnetcorresnifagenttea[.]top` | C2 | AgtaBackup RAT C2 domain |
| `qualityfilesghost[.]live` | C2 | AgtaBackup RAT C2 domain |
| `redjohntiger[.]top` | C2 | AgtaBackup RAT C2 domain |
| `rizkidworikingjuice[.]top` | C2 | AgtaBackup RAT C2 domain |
| `runtownagtabackup[.]top` | C2 | AgtaBackup RAT C2 domain |
| `selfpnl001[.]com` | C2 | AgtaBackup RAT C2 domain |
| `sunbeitnetwork[.]com` | C2 | AgtaBackup RAT C2 domain |
| `unrealjustcoffe[.]top` | C2 | AgtaBackup RAT C2 domain |
| `unrelioaworkinghun[.]top` | C2 | AgtaBackup RAT C2 domain |
| `acrobat-reader-installer[.]com` | Impersonation | Vendor impersonation domain; fake Adobe Acrobat download delivering AgtaBackup RAT |
| `03webzoominvite[.]us` | Impersonation | Vendor impersonation domain; fake Zoom invite delivering AgtaBackup RAT |

### File Hashes (SHA256)
| Hash | Context |
|------|---------|
| `10e0a4861b94b72dd802d0a59f2eac7f8df63f497460aa5252560951fe7b8614` | AgtaBackup RAT — "Credential Guard.exe" (primary payload) |
| `2be4a7b66f6e2fc6759451861ca36589ab6d41566c33226dcac80da15862299d` | AgtaBackup RAT component — installer dropper |
| `5c3267a7855efc96c1144cbfcee937527979d4747c7645b2d36958d43ef3d51f` | AgtaBackup RAT component |
| `a30e8229085407db5ddfe58d33cd7dc4d70fdd0eec29ae0714d77762bbf61393` | AgtaBackup RAT component |
| `c9394752d42fe7b70aa65d91802d4d2a0365c885f27db07460f724395f53ab70` | AgtaBackup RAT component |
| `cfdd8d82fa71383c9ed92d1c21dd64b0eda3d8bb622d71be7205802269fe8e58` | AgtaBackup RAT component |

### Network Indicators
| Indicator | Context |
|-----------|---------|
| HTTP header `X-Agent-Secret: agta-enroll-7f3a1c2d9e` | AgtaBackup RAT enrollment beacon; unique C2 authentication header |
| URI `/api/agents/checkin` | AgtaBackup RAT heartbeat endpoint; 2-second beacon interval |
| TCP port 4080 | AgtaBackup RAT HTTP fallback C2 |
| WebSocket relay | Primary AgtaBackup RAT C2 channel |

---

## 2. TTPs

| Tactic | Technique ID | Technique | Usage |
|--------|-------------|-----------|-------|
| Initial Access | TA0001 | T1566.002 | Spearphishing Link — phishing emails linking to fake backup/RMM software download pages; vendor impersonation (Adobe, Zoom) |
| Execution | TA0002 | T1204.002 | User Execution: Malicious File — victim runs fake backup agent installer |
| Execution | TA0002 | T1218.007 | Signed Binary Proxy Execution: Msiexec — MSI-wrapped installer delivery |
| Defense Evasion | TA0005 | T1036.005 | Masquerade: Match Legitimate Name or Location — payload named "Credential Guard.exe" to impersonate Windows security feature |
| Persistence | TA0003 | T1053.005 | Scheduled Task — scheduled task created for RAT persistence |
| Persistence | TA0003 | T1547.001 | Registry Run Keys — RAT registered for autostart via HKCU Run key |
| Persistence | TA0003 | T1548.004 | Abuse Elevation Control Mechanism: Elevated Execution with Prompt — privilege escalation during install |
| Credential Access | TA0006 | T1555 | Credentials from Password Stores — browser credential harvesting |
| Credential Access | TA0006 | T1056.004 | Input Capture: Credential API Hooking — credential interception |
| Collection | TA0009 | T1113 | Screen Capture — periodic screenshot collection |
| Command and Control | TA0011 | T1071.001 | Application Layer Protocol: Web Protocols — WebSocket primary C2 + HTTP fallback on TCP/4080; unique `X-Agent-Secret` enrollment header |

---

## 3. Malware & Tools

**AgtaBackup RAT** ("Credential Guard.exe")
- **Type:** Custom Windows RAT distributed as fake backup/RMM software
- **Process name:** `Credential Guard.exe` — deliberately named to impersonate the legitimate Windows Credential Guard security feature
- **C2 architecture:**
  - Primary: WebSocket relay with 2-second `/api/agents/checkin` beacon
  - Enrollment: HTTP POST with custom header `X-Agent-Secret: agta-enroll-7f3a1c2d9e`
  - Fallback: HTTP on TCP/4080
- **Capabilities:** Credential harvesting (browsers, credential stores), screen capture, input capture, persistence via scheduled task and registry, file operations
- **Distribution:** 46 domains (44 C2 + 2 vendor impersonation); delivered via phishing emails and fake download pages mimicking Adobe Acrobat, Zoom, and backup software
- **Infrastructure scale:** 44 C2 domains registered across multiple TLDs (.top, .org, .com, .info, .live, .lol, .cyou, .sbs, .one, .help, .online, .cc)

---

## 4. Threat Actor / Campaign Attribution

Unattributed. Active campaign observed in September 2026 by Unit 42 (Palo Alto Networks). The use of vendor impersonation (Adobe, Zoom), broad C2 infrastructure across multiple TLDs, and a custom RAT named to impersonate Windows security components suggests an organized threat actor likely engaged in credential harvesting for financial gain. No overlap with known named APT groups identified in this report.

---

## 5. Splunk Detection Searches

### Detect "Credential Guard.exe" Process Running Outside System32
```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Processes
  where Processes.process_name="Credential Guard.exe"
    AND NOT Processes.process_path="*\\Windows\\System32\\*"
  by Processes.dest Processes.user Processes.parent_process_name
     Processes.process_name Processes.process Processes.process_id
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=100
| table firstTime lastTime dest user parent_process_name process_name process risk_score
```

### Detect Network Connections to AgtaBackup C2 Domains (DNS)
```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Network_Resolution.DNS
  where DNS.query IN (
    "avanade.cc","backupplanetwealthagta.top","beehstwithust.org","blessingsbe.top",
    "bootbackup.com","bootprivate.com","cashyejrudga.live","childofwhho.top",
    "connectprivae.top","criopifileeworking.top","datavaseffhjurd.top","electomm.sbs",
    "emef.info","emsafetoproceedtaward.top","evobasin.info","ghxstworkingagent.top",
    "greateshystfqsh.one","gsop.top","hr4hire.top","installapp.cc","jokermav.online",
    "kresyuhjance.help","llgoldassociates.com","magicislanding.lol","outfitstryon.info",
    "palnetworkingleup.top","piejaholoop.org","planetbizzingupcleananddirt.top",
    "planetvocalfortesttheteas.cyou","planetvocalfortheteas.cyou","planetwealthonlycleancoffe.top",
    "planetwealthonlycleantea.top","planetworkingclassrewor.top","planetworkingfortwo.top",
    "planetwrokingclassforagemt.top","plnetcorresnifagenttea.top","qualityfilesghost.live",
    "redjohntiger.top","rizkidworikingjuice.top","runtownagtabackup.top","selfpnl001.com",
    "sunbeitnetwork.com","unrealjustcoffe.top","unrelioaworkinghun.top",
    "acrobat-reader-installer.com","03webzoominvite.us")
  by DNS.src DNS.query DNS.answer
| `drop_dm_object_name(DNS)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=100
| table firstTime lastTime src query answer risk_score
```

### Detect Outbound HTTP on Non-Standard Port 4080 (AgtaBackup Fallback C2)
```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Network_Traffic.All_Traffic
  where All_Traffic.dest_port=4080
    AND All_Traffic.transport=tcp
  by All_Traffic.src All_Traffic.dest All_Traffic.dest_port All_Traffic.app
| `drop_dm_object_name(All_Traffic)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=80
| where risk_score >= 80
| table firstTime lastTime src dest dest_port app risk_score
```

### Detect Rapid High-Frequency Beaconing (2-Second Interval Pattern)
```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Network_Traffic.All_Traffic
  where All_Traffic.transport=tcp
    AND All_Traffic.dest_port IN (80,443,4080)
  by All_Traffic.src All_Traffic.dest All_Traffic.dest_port _time span=1m
| `drop_dm_object_name(All_Traffic)`
| stats count dc(dest) as unique_dests avg(count) as avg_per_min by src
| where avg_per_min >= 25 AND unique_dests = 1
| eval risk_score=75
| table src unique_dests avg_per_min risk_score
```

---

## 6. Executive Summary

Unit 42 (Palo Alto Networks) published intelligence on September 28, 2026 documenting the **AgtaBackup RAT** campaign, a custom remote access trojan distributed as fake backup software and vendor-impersonating download pages (Adobe Acrobat, Zoom).

**Attack chain:** Victims receive phishing emails or encounter malvertising directing them to vendor-impersonation domains (e.g., `acrobat-reader-installer[.]com`, `03webzoominvite[.]us`) or fake backup software sites. The installer drops a custom RAT named **"Credential Guard.exe"** — deliberately chosen to impersonate the legitimate Windows Credential Guard security feature (`credentialguard.exe` in System32), which can cause analysts and automated tools to deprioritize it during investigation.

**C2 architecture:** The RAT beacons every 2 seconds to `/api/agents/checkin` using a distinctive enrollment HTTP header `X-Agent-Secret: agta-enroll-7f3a1c2d9e`. Primary C2 uses a WebSocket relay; fallback uses HTTP on TCP/4080. The operator maintains 44 C2 domains across 10+ TLDs for resilience.

**Capabilities:** Credential harvesting from browsers and Windows credential stores, input capture, screen capture, file operations, and persistence via scheduled tasks and registry run keys.

**Detection priorities:**
1. Any process named `Credential Guard.exe` running outside `%SystemRoot%\System32` is a confirmed indicator — risk score 100.
2. DNS queries to any of the 46 identified domains are confirmed indicators.
3. Outbound connections to TCP/4080 warrant investigation.

---

## References

- [Unit 42 Timely Threat Intel — AgtaBackup RAT Campaign (2026-09-28)](https://github.com/PaloAltoNetworks/Unit42-timely-threat-intel)
- [MITRE ATT&CK T1036.005 — Masquerade: Match Legitimate Name or Location](https://attack.mitre.org/techniques/T1036/005/)
- [MITRE ATT&CK T1071.001 — Application Layer Protocol: Web Protocols](https://attack.mitre.org/techniques/T1071/001/)
- [MITRE ATT&CK T1555 — Credentials from Password Stores](https://attack.mitre.org/techniques/T1555/)
