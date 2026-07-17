# Spirals Ransomware: IIS Webshell Execution and WMI Mass Lateral Movement

## Description

Detects the attack chain used by the Spirals ransomware operator, which achieved full network encryption of an IT services firm in South Asia in under 24 hours in June 2026. The actor gained initial access by deploying an ASP.NET webshell on an internet-facing IIS server (T1505.003), then escalated privileges via UAC bypass, created a local administrator account, enabled RDP, and dumped SAM and LSASS credentials. Using those credentials, the actor established persistent C2 tunnels via revsocks, Chisel, and Cloudflare Tunnel, removed security software from all target hosts, then used WMI to push the ransomware payload to 12 or more hosts simultaneously. The Rust-based Spirals ransomware uses AES-128 encryption with ECDH P-256 key exchange and applies intermittent encryption to files larger than 5 MB to maximize spread speed. The ransom note is named `RECOVERY_SECTION.log`. Payload delivery to remote hosts used `bitsadmin.exe` to masquerade transfers as legitimate BITS jobs.

Detection signals are provided for four phases of the attack: IIS webshell execution (w3wp.exe spawning command interpreters), WMI mass lateral movement (≥5 unique remote hosts in a 5-minute window), ransom note creation (RECOVERY_SECTION.log), and bitsadmin payload delivery from shell/webshell context.

False positives: w3wp.exe spawning cmd.exe can occur in IIS environments with custom admin automation or legacy ASP applications. Context from the spawned command (whoami, net, bitsadmin with downloads) distinguishes post-exploitation from legitimate use. WMI connections to multiple hosts are common in enterprise management workflows — filter on account context (service accounts vs. interactive user accounts) and volume thresholds.

## MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| Tactic | Impact, Initial Access, Execution, Lateral Movement |
| Tactic ID | TA0040, TA0001, TA0002, TA0008 |
| Technique | Data Encrypted for Impact; Exploit Public-Facing Application; Web Shell; Windows Management Instrumentation; BITS Jobs; Protocol Tunneling |
| Technique ID | T1486, T1190, T1505.003, T1047, T1197, T1572 |

## Lockheed Martin Kill Chain

| Phase |
|-------|
| Exploitation |
| Installation |
| Actions on Objectives |

## Splunk Detection Query

### Query 1: IIS Worker Process Spawning Command Shell (Webshell Execution)

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Endpoint.Processes
where Processes.parent_process_name="w3wp.exe"
  AND Processes.process_name IN ("cmd.exe", "powershell.exe", "powershell_ise.exe",
    "wscript.exe", "cscript.exe", "mshta.exe", "certutil.exe", "bitsadmin.exe",
    "curl.exe", "wget.exe", "whoami.exe", "net.exe", "net1.exe")
by Processes.dest Processes.user Processes.parent_process_name
   Processes.process_name Processes.process Processes.process_id
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=75
| table firstTime lastTime dest user parent_process_name process_name process risk_score
```

### Query 2: WMI Lateral Movement to Multiple Unique Hosts

```spl
| tstats `security_content_summariesonly` count dc(Processes.dest) as unique_dest_count
  min(_time) as firstTime max(_time) as lastTime
from datamodel=Endpoint.Processes
where Processes.process_name IN ("wmic.exe", "wmiprvse.exe")
  AND Processes.process IN ("*/node:*", "* /node:*")
by Processes.user Processes.process_name _time span=5m
| `drop_dm_object_name(Processes)`
| where unique_dest_count >= 5
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(unique_dest_count >= 12, 85, unique_dest_count >= 5, 65, 1=1, 50)
| where risk_score >= 65
| table firstTime lastTime user process_name unique_dest_count risk_score
```

### Query 3: RECOVERY_SECTION.log Ransom Note Creation

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Endpoint.Filesystem
where Filesystem.file_name="RECOVERY_SECTION.log"
by Filesystem.dest Filesystem.user Filesystem.file_path Filesystem.file_name Filesystem.process_name
| `drop_dm_object_name(Filesystem)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=100
| table firstTime lastTime dest user file_path file_name process_name risk_score
```

### Query 4: bitsadmin.exe Download Spawned from Web or Shell Context

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Endpoint.Processes
where Processes.process_name="bitsadmin.exe"
  AND (Processes.process IN ("*/transfer*", "*/addfile*", "*/download*", "*/create*")
    OR Processes.process IN ("*http://*", "*https://*"))
  AND Processes.parent_process_name IN ("cmd.exe", "powershell.exe", "w3wp.exe",
    "wscript.exe", "cscript.exe")
by Processes.dest Processes.user Processes.parent_process_name
   Processes.process_name Processes.process Processes.process_id
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    match(parent_process_name, "(?i)w3wp"), 85,
    1=1, 65)
| where risk_score >= 65
| table firstTime lastTime dest user parent_process_name process_name process risk_score
```

## Risk Score Logic

| Condition | Score | Rationale |
|-----------|-------|-----------|
| w3wp.exe spawning cmd.exe, PowerShell, or other interpreters | 75 | Classic webshell execution indicator; IIS worker process has no legitimate reason to spawn interactive shells |
| WMI to ≥12 unique remote hosts in a 5-minute window | 85 | Matches Spirals mass lateral movement pattern; 12+ simultaneous hosts is above any legitimate enterprise management volume |
| WMI to ≥5 unique remote hosts in a 5-minute window | 65 | Suspicious volume; likely ransomware spreading or mass deployment |
| RECOVERY_SECTION.log created anywhere on filesystem | 100 | Spirals ransomware ransom note; high-confidence ransomware detonation |
| bitsadmin.exe spawned from w3wp.exe | 85 | Webshell using BITS for payload download; no legitimate IIS application uses bitsadmin |
| bitsadmin.exe with download flags spawned from cmd.exe/PowerShell | 65 | Living-off-the-land payload delivery; suspicious when combined with other IIS indicators |

## Associated Threat Actors

| Actor | References |
|-------|-----------|
| Unknown (Spirals ransomware operator) | [BleepingComputer — Spirals Ransomware (2026-07-17)](https://www.bleepingcomputer.com/news/security/new-spirals-ransomware-encrypts-victim-network-in-under-24-hours/) |

## References

- [BleepingComputer — New Spirals Ransomware Encrypts Victim Network in Under 24 Hours (2026-07-17)](https://www.bleepingcomputer.com/news/security/new-spirals-ransomware-encrypts-victim-network-in-under-24-hours/)
- [MITRE ATT&CK — T1486: Data Encrypted for Impact](https://attack.mitre.org/techniques/T1486/)
- [MITRE ATT&CK — T1505.003: Web Shell](https://attack.mitre.org/techniques/T1505/003/)
- [MITRE ATT&CK — T1047: Windows Management Instrumentation](https://attack.mitre.org/techniques/T1047/)
- [MITRE ATT&CK — T1190: Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/)
- [MITRE ATT&CK — T1197: BITS Jobs](https://attack.mitre.org/techniques/T1197/)
- [MITRE ATT&CK — T1572: Protocol Tunneling](https://attack.mitre.org/techniques/T1572/)
