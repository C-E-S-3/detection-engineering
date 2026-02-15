# Gootloader Obfuscated JavaScript File Creation

## Description

Gootloader drops heavily obfuscated JavaScript files with characteristic large file sizes (typically 40 KB+). This detection identifies `.js` file creation events in user-writable directories that may indicate Gootloader staging after a victim downloads and extracts the malicious ZIP archive.

False positive sources: Legitimate web development workflows, npm/node_modules activity. Tuning: exclude known development directories.

## MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| Tactic | Initial Access |
| Tactic ID | TA0001 |
| Technique | User Execution: Malicious File |
| Technique ID | T1204.002 |

## Lockheed Martin Kill Chain

| Phase |
|-------|
| Delivery |

## Splunk Detection Query

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Endpoint.Filesystem
where Filesystem.file_name="*.js"
    AND (Filesystem.file_path IN ("*\\Downloads\\*", "*\\Temp\\*", "*\\AppData\\*", "*\\Desktop\\*"))
by Filesystem.dest Filesystem.user Filesystem.file_name Filesystem.file_path Filesystem.process_name
| `drop_dm_object_name(Filesystem)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    match(file_path, "(?i)\\\\Temp\\\\"), 70,
    match(file_path, "(?i)\\\\Downloads\\\\"), 65,
    1=1, 50)
| where risk_score >= 50
| table firstTime lastTime dest user file_name file_path process_name risk_score
```

## Risk Score Logic

| Condition | Score | Rationale |
|-----------|-------|-----------|
| JS file created in Temp directory | 70 | Temp is a common staging path for malware |
| JS file created in Downloads directory | 65 | Downloads is the expected Gootloader delivery path |
| JS file created in other user directories | 50 | Lower confidence but still anomalous |

## Associated Threat Actors

| Actor | References |
|-------|-----------|
| Gootloader / UNC2565 | [MITRE - Gootloader (S1138)](https://attack.mitre.org/software/S1138/) |

## References

- [Mandiant - Tracking and Disrupting GootLoader Operations](https://www.mandiant.com/resources/tracking-and-disrupting-gootloader-operations)
