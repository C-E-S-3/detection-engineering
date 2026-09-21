# APT36 RUSTYMOVE — USB Removable Media Malware Propagation

## Description

Detects RUSTYMOVE, a Rust-based Windows post-compromise tool used by APT36 (Transparent Tribe, Operation RapidRust) to propagate malware to air-gapped networks via removable media. RUSTYMOVE continuously scans for attached USB drives, SD cards, and MMC devices, then copies pre-staged malicious files to all detected media.

Three queries cover this technique:
1. **Repeated removable storage device enumeration** — a process repeatedly calling WMI or Win32 APIs to list removable drives in rapid succession
2. **Executable file creation on non-system drives** — malicious binary or script written to removable media (D: and above) by an unexpected process
3. **Batch file writes to removable media** — high-volume file write activity to external drives by a single process (typical of a tool copying a full malware package)

False positives include backup software writing to external drives, legitimate USB synchronization tools, Robocopy/xcopy scripts, and installers placing files on USB boot media. Tune the excluded process list for your environment. Drive letter heuristics are imperfect — confirm with USB device connection events (Windows 4663/System EventLog) for validation.

## MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| Tactic | Lateral Movement |
| Tactic ID | TA0008 |
| Technique | Replication Through Removable Media |
| Technique ID | T1091 |

Secondary: T1105 (Ingress Tool Transfer — RUSTYMOVE loading additional payloads from staged media), T1025 (Data from Removable Media — potential data theft component)

## Lockheed Martin Kill Chain

| Phase |
|-------|
| Actions on Objectives |

## Splunk Detection Query

### Query 1 — Executable Dropped to Removable Media by Non-System Process

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Filesystem
  where Filesystem.action IN ("created","modified")
    AND Filesystem.file_name IN ("*.exe","*.dll","*.ps1","*.bat","*.lnk","*.vbs","*.hta","*.js","*.wsf","*.com","*.scr")
  by Filesystem.dest Filesystem.user Filesystem.process_name Filesystem.process_id
     Filesystem.file_name Filesystem.file_path
| `drop_dm_object_name(Filesystem)`
| where match(file_path, "^[D-Z]:\\\\")
| search NOT process_name IN ("explorer.exe","robocopy.exe","xcopy.exe","setup.exe","installer.exe","msiexec.exe","dfrgui.exe")
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    process_name IN ("psnatch.exe","bashnatch.exe","rustymove.exe","rustyshade.exe"), 98,
    like(file_name,"%.exe") OR like(file_name,"%.dll"), 85,
    like(file_name,"%.lnk") OR like(file_name,"%.ps1"), 80,
    1=1, 70)
| where risk_score >= 70
| table firstTime lastTime dest user process_name file_name file_path risk_score
```

### Query 2 — High-Volume File Writes to Removable Media (Single Process)

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Filesystem
  where Filesystem.action IN ("created","modified")
  by Filesystem.dest Filesystem.user Filesystem.process_name Filesystem.process_id Filesystem.file_path _time span=5m
| `drop_dm_object_name(Filesystem)`
| where match(file_path, "^[D-Z]:\\\\")
| stats max(count) as max_per_5min by dest user process_name process_id
| where max_per_5min > 20
| search NOT process_name IN ("robocopy.exe","xcopy.exe","rsync.exe","backup.exe","veeam*.exe","msiexec.exe")
| eval risk_score=case(max_per_5min > 100, 90, max_per_5min > 50, 80, max_per_5min > 20, 70, 1=1, 60)
| where risk_score >= 70
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| table firstTime lastTime dest user process_name process_id max_per_5min risk_score
```

### Query 3 — Process Repeatedly Enumerating Removable Drives (WMI / PowerShell)

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Processes
  where
    (Processes.process="*Win32_LogicalDisk*" AND Processes.process="*DriveType*")
    OR Processes.process="*Get-WmiObject*Win32_DiskDrive*"
    OR Processes.process="*Get-PSDrive*"
  by Processes.dest Processes.user Processes.process_name Processes.parent_process_name
     Processes.process Processes.process_id _time span=10m
| `drop_dm_object_name(Processes)`
| stats count as query_count min(firstTime) as firstTime max(lastTime) as lastTime by dest user process_name parent_process_name process
| where query_count > 3
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(query_count > 20, 85, query_count > 10, 75, query_count > 3, 65, 1=1, 55)
| where risk_score >= 65
| table firstTime lastTime dest user process_name parent_process_name query_count risk_score
```

## Risk Score Logic

| Condition | Score | Rationale |
|-----------|-------|-----------|
| Exact process name match (psnatch, bashnatch, rustymove, rustyshade) | 98 | Direct IOC hit — these process names have no legitimate use |
| PE/DLL created on removable media by non-backup process | 85 | Strong indicator of malware propagation; legitimate tools don't write executables to USB in enterprise environments |
| LNK or PS1 created on removable media | 80 | Common malware propagation format (LNK worms) |
| Any executable file created on removable media | 70 | Baseline suspicious activity requiring investigation |
| High-volume file writes to removable media (>100 files/5min) | 90 | Consistent with automated bulk file copy by RUSTYMOVE |
| Repeated WMI removable-drive enumeration (>10 calls/10min) | 75 | Consistent with RUSTYMOVE continuous scanning loop |

## Associated Threat Actors

| Actor | References |
|-------|-----------|
| APT36 (Transparent Tribe, G0134) | [MITRE ATT&CK G0134](https://attack.mitre.org/groups/G0134/); [Zscaler Operation RapidRust (Sep 2026)](https://www.zscaler.com/blogs/security-research/operation-rapidrust-apt36-deploys-rustyshade-rustymove-psnatch-and-bashnatch) |
| CryptoBandits (USB LNK Worm) | [Initial Access: USB LNK Worm detection](../initial_access/cryptobandits_usb_lnk_worm_crypto_clipper.md) |

## References

- [Zscaler ThreatLabz: Operation RapidRust — RUSTYMOVE technical details](https://www.zscaler.com/blogs/security-research/operation-rapidrust-apt36-deploys-rustyshade-rustymove-psnatch-and-bashnatch)
- [MITRE ATT&CK: T1091 — Replication Through Removable Media](https://attack.mitre.org/techniques/T1091/)
- [MITRE ATT&CK: APT36 (G0134)](https://attack.mitre.org/groups/G0134/)
- [Threat Intel: 2026-09-19_zscaler-apt36-operation-rapidrust-rustyshade-rustymove.md]
