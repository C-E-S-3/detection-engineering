# Malicious Service Installation for Persistence

## Description

Detects kernel driver and user-mode service installation used by attackers to establish persistent access or deploy BYOVD (Bring Your Own Vulnerable Driver) tooling. This covers both sc.exe-based service creation and direct Registry modification to the HKLM\SYSTEM\CurrentControlSet\Services hive. Distinct from the BYOVD-specific detections in defense_evasion/ — this focuses on the installation event itself and catches a broader range of malicious service deployments (C2 agent services, ransomware loader services, RMM service installations). Common false positives: legitimate software installers and Windows Update; filter by process lineage (SYSTEM/TrustedInstaller parents are typically benign), file signature status, and path (non-Program Files paths are higher risk).

## MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| Tactic | Persistence |
| Tactic ID | TA0003 |
| Technique | Create or Modify System Process: Windows Service |
| Technique ID | T1543.003 |

## Lockheed Martin Kill Chain

| Phase |
|-------|
| Installation |

## Splunk Detection Query

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Services
  where Services.start_mode IN ("auto","demand")
    AND NOT Services.user IN ("SYSTEM","NT AUTHORITY\\SYSTEM","LocalSystem")
  by Services.dest Services.user Services.service_name Services.service_path
     Services.service_dll_path Services.start_mode
| `drop_dm_object_name(Services)`
| eval risk_score=case(
    NOT match(service_path, "(?i)C:\\\\Windows|C:\\\\Program Files|C:\\\\Program Files \\(x86\\)"), 85,
    match(service_path, "(?i)\\\\temp\\\\|\\\\tmp\\\\|\\\\appdata\\\\|\\\\users\\\\public\\\\"), 90,
    1=1, 60)
| where risk_score >= 60
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| table firstTime lastTime dest user service_name service_path start_mode risk_score
```

**Supplemental: sc.exe service creation from non-administrative context**

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Processes
  where Processes.process_name="sc.exe"
    AND (Processes.process="*create*" OR Processes.process="*config*start=*")
    AND NOT Processes.parent_process_name IN ("msiexec.exe","TrustedInstaller.exe",
        "services.exe","svchost.exe")
  by Processes.dest Processes.user Processes.parent_process_name
     Processes.process_name Processes.process Processes.process_id
| `drop_dm_object_name(Processes)`
| eval risk_score=case(
    match(process, "(?i)start=\\s*auto") AND match(parent_process_name, "(?i)cmd|powershell|wscript"), 90,
    match(process, "(?i)binPath.*\\\\temp|binPath.*\\\\appdata|binPath.*\\\\users\\\\public"), 95,
    match(process, "(?i)sc.*create"), 75,
    1=1, 65)
| where risk_score >= 65
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| table firstTime lastTime dest user parent_process_name process_name process risk_score
```

**Supplemental: Registry-based service key creation**

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Registry
  where Registry.registry_path="HKLM\\SYSTEM\\CurrentControlSet\\Services\\*"
    AND Registry.action IN ("created","modified")
    AND Registry.registry_key_name IN ("ImagePath","ServiceDll","Type","Start")
    AND NOT Registry.process_name IN ("services.exe","TrustedInstaller.exe","msiexec.exe",
        "svchost.exe","wuauclt.exe")
  by Registry.dest Registry.user Registry.process_name Registry.registry_path Registry.registry_value_data
| `drop_dm_object_name(Registry)`
| eval risk_score=case(
    match(registry_value_data, "(?i)\\\\temp\\\\|\\\\appdata\\\\|\\\\users\\\\public"), 90,
    NOT match(registry_value_data, "(?i)C:\\\\Windows|C:\\\\Program Files"), 80,
    1=1, 65)
| where risk_score >= 65
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| table firstTime lastTime dest user process_name registry_path registry_value_data risk_score
```

## Risk Score Logic

| Condition | Score | Rationale |
|-----------|-------|-----------|
| Service binary in %TEMP%, %APPDATA%, or public paths | 90-95 | Near-certain malicious; legitimate services never install to temp directories |
| sc.exe create with auto-start from cmd/PowerShell parent | 90 | Attacker service deployment; IT uses MSI/SCCM, not interactive sc.exe |
| Service binary outside Program Files/Windows | 85 | Non-standard path; high suspicion without corresponding signed installer |
| Registry ServiceDll/ImagePath written by non-services.exe | 65-80 | Direct registry manipulation to register a new service; review process |

## Associated Threat Actors

| Actor | Relationship to Detection |
|-------|--------------------------|
| Scattered Spider (UNC3944) | Installs RMM tools as persistent services for re-entry after initial eviction |
| LockBit Affiliates | Deploy ransomware loaders as services for pre-execution staging |
| Conti / Black Basta | Service installation is standard playbook step after lateral movement |
| Lazarus Group (HIDDEN COBRA) | Malicious services used to maintain long-term persistence on high-value targets |
| BYOVD Actors (various) | Vulnerable driver services created via sc.exe (covered in detail by defense_evasion/byovd_* detections) |

## References

- [MITRE ATT&CK - T1543.003 Create or Modify System Process: Windows Service](https://attack.mitre.org/techniques/T1543/003/)
- [CISA - Malicious Use of Legitimate Remote Monitoring and Management Software](https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-025a)
- [MITRE ATT&CK - T1219 Remote Access Software](https://attack.mitre.org/techniques/T1219/)
