# Gootloader Registry Stuffing - Large Registry Value Writes

## Description

A hallmark of Gootloader is storing encoded payloads in the Windows registry (registry stuffing). The malware writes large base64-encoded or hex-encoded blobs to registry keys under `HKCU\SOFTWARE\<random>`. This detection identifies PowerShell or wscript writing values to HKCU\SOFTWARE registry paths, which may contain encoded second and third stage payloads. This technique avoids writing payloads to disk.

False positive sources: Some legitimate software stores configuration in HKCU\SOFTWARE. Tuning: correlate with process lineage (wscript parent) for higher confidence.

## MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| Tactic | Persistence |
| Tactic ID | TA0003 |
| Technique | Modify Registry |
| Technique ID | T1112 |

## Lockheed Martin Kill Chain

| Phase |
|-------|
| Installation |

## Splunk Detection Query

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Endpoint.Registry
where (Registry.process_name IN ("powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe"))
    AND Registry.registry_path="HKEY_CURRENT_USER\\SOFTWARE\\*"
    AND Registry.action="modified"
by Registry.dest Registry.user Registry.process_name Registry.registry_path
   Registry.registry_key_name Registry.registry_value_name
| `drop_dm_object_name(Registry)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    match(process_name, "(?i)wscript"), 80,
    match(process_name, "(?i)powershell"), 75,
    1=1, 55)
| table firstTime lastTime dest user process_name registry_path registry_key_name registry_value_name risk_score
```

## Risk Score Logic

| Condition | Score | Rationale |
|-----------|-------|-----------|
| Wscript modifying HKCU\SOFTWARE | 80 | High-confidence Gootloader registry stuffing pattern |
| PowerShell modifying HKCU\SOFTWARE | 75 | Consistent with Gootloader second stage |
| Other script interpreters | 55 | Suspicious but less specific |

## Associated Threat Actors

| Actor | References |
|-------|-----------|
| Gootloader / UNC2565 | [MITRE - Gootloader (S1138)](https://attack.mitre.org/software/S1138/) |

## References

- [Mandiant - Tracking and Disrupting GootLoader Operations](https://www.mandiant.com/resources/tracking-and-disrupting-gootloader-operations)
- [MITRE ATT&CK - Modify Registry (T1112)](https://attack.mitre.org/techniques/T1112/)
