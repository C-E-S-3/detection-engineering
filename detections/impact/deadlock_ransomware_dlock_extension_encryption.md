# DeadLock Ransomware: .dlock Encrypted File Extension and Pre-Encryption Activity

## Description

Detects DeadLock ransomware activity across three behavioral layers: encrypted file creation (`.dlock` extension), registry modifications used for extension icon hijacking and wallpaper defacement, and pre-encryption preparation steps including event log clearing, VSS deletion, and Windows Defender / backup service termination.

DeadLock is a Rust-based RaaS encryptor using XChaCha20 + Curve25519 ECDH (NaCl `crypto_box`) with ephemeral per-file keys. It appends `.dlock` to all encrypted files, drops `HOW_RECOVER.<UID>.txt` and `RECOVERY_CHAT.<UID>.html` ransom notes, and uses a novel Polygon blockchain + Session onion-network decentralized recovery infrastructure with no traditional C2 server. The operator is linked to Lynx and INC ransomware affiliate ecosystems.

**False positives:** The `.dlock` file extension check should have no false positives in typical environments. The registry wallpaper key is written by legitimate Windows personalization operations, so that sub-query may produce low-volume noise; tune with an allowlist of known-benign change agents if needed. The process-based query for `vssadmin.exe delete shadows` is high-confidence malicious; `sc.exe stop` and `wevtutil.exe cl` have some administrative use — evaluate with parent process context.

## MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| Tactic | Impact |
| Tactic ID | TA0040 |
| Technique | Data Encrypted for Impact |
| Technique ID | T1486 |
| Secondary Techniques | T1490 (Inhibit System Recovery), T1489 (Service Stop), T1070.001 (Clear Windows Event Logs), T1491.001 (Internal Defacement) |

## Lockheed Martin Kill Chain

| Phase |
|-------|
| Actions on Objectives |

## Splunk Detection Query

**Query 1 — Encrypted File Extension (.dlock)**

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Filesystem
  where Filesystem.file_name="*.dlock"
  by Filesystem.dest Filesystem.user Filesystem.file_path Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=100
| table firstTime lastTime dest user file_name file_path risk_score
```

**Query 2 — Registry Modification: .dlock Icon and Wallpaper Defacement**

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Registry
  where Registry.registry_path="*\\Classes\\.dlock*"
     OR Registry.registry_path="*\\CurrentVersion\\Policies\\System\\Wallpaper*"
  by Registry.dest Registry.user Registry.registry_path Registry.registry_value_data
| `drop_dm_object_name(Registry)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    match(registry_path, "(?i)Classes\\\\.dlock"), 95,
    match(registry_path, "(?i)Policies\\\\System\\\\Wallpaper"), 60,
    1=1, 50)
| where risk_score >= 60
| table firstTime lastTime dest user registry_path registry_value_data risk_score
```

**Query 3 — Pre-Encryption Activity: Event Log Clearing, VSS Deletion, Security Service Termination**

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Processes
  where (Processes.process_name="wevtutil.exe" AND Processes.process="*cl *")
     OR (Processes.process_name="sc.exe" AND Processes.process="*stop*"
         AND (Processes.process="*vss*" OR Processes.process="*VSS*" OR Processes.process="*WinDefend*"))
     OR (Processes.process_name="vssadmin.exe" AND Processes.process="*delete shadows*")
  by Processes.dest Processes.user Processes.parent_process_name
     Processes.process_name Processes.process Processes.process_id
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    match(process, "(?i)delete shadows"), 95,
    match(process, "(?i)WinDefend"), 85,
    match(process, "(?i)vss"), 80,
    match(process_name, "(?i)wevtutil"), 80,
    1=1, 70)
| where risk_score >= 70
| table firstTime lastTime dest user parent_process_name process_name process risk_score
```

## Risk Score Logic

| Condition | Score | Rationale |
|-----------|-------|-----------|
| `.dlock` file extension created (Query 1) | 100 | Extension is unique to DeadLock ransomware; no legitimate use |
| `HKLM\...\Classes\.dlock` registry key created (Query 2) | 95 | DeadLock-specific icon registration; no legitimate use |
| `HKLM\...\Policies\System\Wallpaper` modified (Query 2) | 60 | DeadLock sets custom wallpaper but this key also set by legitimate GPO/personalization |
| `vssadmin.exe delete shadows` (Query 3) | 95 | Shadow copy deletion is ransomware-canonical; rarely legitimate in endpoint context |
| `sc.exe stop WinDefend` (Query 3) | 85 | Disabling Windows Defender strongly indicates malicious intent |
| `sc.exe stop vss` (Query 3) | 80 | Stopping VSS directly impairs backup recovery |
| `wevtutil.exe cl` (Query 3) | 80 | Clearing Windows event logs is a common forensic anti-recovery step |

## Associated Threat Actors

| Actor | References |
|-------|-----------|
| DeadLock Ransomware | [Microsoft Security Blog — DeadLock Ransomware Deep Dive (2026-08-10)](https://www.microsoft.com/en-us/security/blog/2026/08/10/deadlock-ransomware-breaking-down-a-rust-based-encryptor-with-decentralized-recovery-infrastructure/) |
| Lynx Ransomware (affiliate overlap) | [MITRE ATT&CK](https://attack.mitre.org/groups/) |
| INC Ransomware (affiliate overlap) | [MITRE ATT&CK](https://attack.mitre.org/groups/) |

## References

- [Microsoft Security Blog — DeadLock Ransomware: Rust-Based Encryptor with Polygon Blockchain Decentralized Recovery Infrastructure (2026-08-10)](https://www.microsoft.com/en-us/security/blog/2026/08/10/deadlock-ransomware-breaking-down-a-rust-based-encryptor-with-decentralized-recovery-infrastructure/)
- [Threat Intel Report — 2026-08-14](../../threat-intel/2026-08-14_microsoft-com-security-blog-deadlock-ransomware-rust-encryptor.md)
- [MITRE ATT&CK — T1486: Data Encrypted for Impact](https://attack.mitre.org/techniques/T1486/)
- [MITRE ATT&CK — T1490: Inhibit System Recovery](https://attack.mitre.org/techniques/T1490/)
- [MITRE ATT&CK — T1070.001: Clear Windows Event Logs](https://attack.mitre.org/techniques/T1070/001/)
- [MITRE ATT&CK — T1489: Service Stop](https://attack.mitre.org/techniques/T1489/)
