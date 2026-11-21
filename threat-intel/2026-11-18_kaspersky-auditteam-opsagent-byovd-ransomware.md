---
scraped_at: 2026-11-21T00:00:00Z
source_url: https://securelist.com/auditteam-opsagent-forced-audit/122031/
report_type: threat-intel
severity: high
title: "AuditTeam Ransomware: OpsAgent Modular Framework with BYOVD EDR Kill Using Jiangmin Antivirus Driver"
---

# AuditTeam Ransomware: OpsAgent Modular Framework with BYOVD EDR Kill Using Jiangmin Antivirus Driver

**Source:** Kaspersky GReAT (Securelist)
**Published:** 2026-11-18
**Severity:** High

---

## 1. IOCs

### File Artifacts

| Artifact | Type | Context |
|---------|------|---------|
| kvcore.sys | Kernel driver | Beijing Jiangmin Antivirus KV series driver; legitimately signed; deployed by AuditTeam via BYOVD to kill security tool processes; communicates via `\KvCorePortX0` filter port |
| HEUR:Backdoor.Win64.OpsAgent.gen | Kaspersky detection name | Generic Kaspersky signature for OpsAgent implant family |

> **Note:** Specific file hashes, C2 IPs, and C2 domains were not available from accessible sources at time of ingestion. Retrieve the full IOC appendix from the Securelist report at securelist.com/auditteam-opsagent-forced-audit/122031/

### Process Injection Hosts

OpsAgent injects into legitimate Windows processes used as runtime C2 hosts. Observed processes:
- `msiexec.exe` — Microsoft Windows Installer; hijacked for C2 communication
- `notepad.exe` — Windows Notepad; hijacked for C2 communication

---

## 2. TTPs

| Tactic | Technique ID | Technique Name | Usage |
|--------|-------------|----------------|-------|
| Initial Access | T1566 | Phishing | Initial delivery via spearphishing; actors impersonate security audit firms |
| Defense Evasion | T1562.001 | Impair Defenses: Disable or Modify Tools | BYOVD using legitimately signed kvcore.sys to kill ~220 security tool processes |
| Defense Evasion | T1543.003 | Create or Modify System Process: Windows Service | kvcore.sys deployed as a kernel driver service |
| Defense Evasion | T1036.004 | Masquerading: Masquerade Task or Service | Driver disguised as Beijing Jiangmin Antivirus (KV series) |
| Defense Evasion | T1070.004 | Indicator Removal: File Deletion | Shadow copy deletion prior to ransomware encryption |
| Execution | T1055 | Process Injection | OpsAgent implant injected into msiexec.exe and notepad.exe as C2 host processes |
| Execution | T1059 | Command and Scripting Interpreter | Loaders in C, .NET, and Rust variants unpack and inject the implant |
| Persistence | T1543.003 | Windows Service | Kernel driver service persists across reboots |
| Lateral Movement | T1570 | Lateral Tool Transfer | Interactive shell capability added in Rust-rewrite variant |
| Command and Control | T1071 | Application Layer Protocol | C2 upgraded from HTTP polling to persistent TLS WebSocket in Rust variant |
| Impact | T1486 | Data Encrypted for Impact | Ransomware module encrypts files; kills database processes before encryption |
| Impact | T1490 | Inhibit System Recovery | Shadow copies deleted before encryption |

---

## 3. Malware & Tools

| Name | Type | Description |
|------|------|-------------|
| **OpsAgent** | Modular backdoor/ransomware framework | Multi-stage Rust/C++/.NET framework; initial C++ version evolved to Rust; adds interactive shell and WebSocket C2; Kaspersky detection: HEUR:Backdoor.Win64.OpsAgent.gen |
| **kvcore.sys** | BYOVD kernel driver | Legitimately signed Beijing Jiangmin Antivirus KV series driver; AuditTeam weaponizes it to terminate ~220 security processes via `\KvCorePortX0` kernel filter port |

### Kill List (partial — sources vary)
The EDR kill list contains approximately 220 process names including: Microsoft Defender, ESET, Kaspersky, Sysmon, Splunk agents, and database services (killed before encryption to unlock files).

---

## 4. Threat Actor / Campaign Attribution

| Attribute | Value |
|-----------|-------|
| Group name | AuditTeam |
| Attribution confidence | High (Kaspersky GReAT) |
| Campaign posture | Actors impersonate security audit firms; ransom demand is framed as an "Audit & Consulting fee" |
| Ransom note framing | Promises a "vulnerability report" if victim pays; threatens data publication otherwise |
| Campaign timeline | First detection: 2026-03-10 (Hong Kong); first victim on leak site: 2026-02-21; active through October 2026 |
| Known victim countries | China, Finland, Hong Kong, Italy, Philippines, Russia, Senegal |
| Sector | Broad; multiple industries |
| Attribution | Unknown; Kaspersky does not assign nation-state attribution in the report |

---

## 5. Splunk Detection Searches

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Services
  where (Services.service_path="*kvcore*" OR Services.service_path="*KvCore*")
  by Services.dest Services.service_name Services.service_path Services.start_mode
| `drop_dm_object_name(Services)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=90
| table firstTime lastTime dest service_name service_path start_mode risk_score
```

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Processes
  where (Processes.process_name="sc.exe" OR Processes.process_name="services.exe")
    AND (Processes.process="*kvcore*" OR Processes.process="*KvCorePort*")
  by Processes.dest Processes.user Processes.parent_process_name
     Processes.process_name Processes.process Processes.process_id
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=90
| table firstTime lastTime dest user parent_process_name process_name process risk_score
```

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Processes
  where (Processes.process_name="msiexec.exe" OR Processes.process_name="notepad.exe")
  by Processes.dest Processes.user Processes.parent_process_name
     Processes.process_name Processes.process Processes.process_id Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| where process_path!="C:\\Windows\\System32\\msiexec.exe"
    AND process_path!="C:\\Windows\\SysWOW64\\msiexec.exe"
    AND process_path!="C:\\Windows\\System32\\notepad.exe"
| eval risk_score=80
| table firstTime lastTime dest user parent_process_name process_name process process_path risk_score
```

```spl
index=wineventlog EventCode=7045
| where like(lower(ServiceFileName), "%kvcore%") OR like(lower(ServiceName), "%kvcore%")
    OR like(lower(ServiceName), "%jiangmin%") OR like(lower(ServiceName), "%kvcoreport%")
| eval risk_score=90
| `security_content_ctime(_time)`
| table _time dest ServiceName ServiceFileName ServiceType risk_score
```

---

## 6. Executive Summary

AuditTeam is a ransomware group first active in early 2026, posing as security audit consultants. Their toolkit — OpsAgent — is a modular framework that evolved from C++ to Rust during the campaign, adding an interactive shell and upgrading C2 from HTTP polling to persistent TLS WebSocket connections.

The most distinctive AuditTeam TTP is BYOVD EDR evasion: they deploy `kvcore.sys`, a legitimately signed Beijing Jiangmin Antivirus driver, to kill approximately 220 security tool processes (including Defender, ESET, Kaspersky, Sysmon, and Splunk) via the `\KvCorePortX0` kernel filter port before deploying ransomware. Database processes are killed immediately before file encryption to unlock files.

Kaspersky attributed the campaign to AuditTeam with high confidence after investigating intrusions across seven countries. The group has an active data leak site. Kaspersky detection is `HEUR:Backdoor.Win64.OpsAgent.gen`.

**Recommended actions:** Alert on `kvcore.sys` or any Beijing Jiangmin Antivirus driver loading on hosts that do not run Jiangmin products; monitor for msiexec.exe or notepad.exe running from non-standard paths (indicating process injection); enable Sysmon Event ID 6 (kernel driver loading) with filtering for unexpected AV vendors.
