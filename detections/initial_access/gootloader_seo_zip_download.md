# Gootloader ZIP Archive with Embedded JavaScript Downloaded via Browser

## Description

Gootloader distributes payloads as ZIP files containing a single JavaScript file. Users reach the download via SEO-poisoned search results on compromised WordPress sites. This detection identifies browser processes writing ZIP files to user directories followed by JavaScript file creation from archive extraction within a 5-minute window.

False positive sources: Legitimate ZIP downloads containing JS files (rare in enterprise environments). Tuning: whitelist known developer-related download patterns.

## MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| Tactic | Initial Access |
| Tactic ID | TA0001 |
| Technique | Drive-by Compromise |
| Technique ID | T1189 |
| Secondary Technique | User Execution: Malicious File (T1204.002) |

## Lockheed Martin Kill Chain

| Phase |
|-------|
| Delivery |

## Splunk Detection Query

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Endpoint.Filesystem
where Filesystem.file_name="*.zip"
    AND Filesystem.file_path IN ("*\\Downloads\\*", "*\\Temp\\*", "*\\Desktop\\*")
    AND Filesystem.process_name IN ("chrome.exe", "msedge.exe", "firefox.exe", "iexplore.exe", "browser_broker.exe")
by Filesystem.dest Filesystem.user Filesystem.file_name Filesystem.file_path Filesystem.process_name
| `drop_dm_object_name(Filesystem)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| join dest user
    [| tstats `security_content_summariesonly` count min(_time) as js_firstTime max(_time) as js_lastTime
     from datamodel=Endpoint.Filesystem
     where Filesystem.file_name="*.js"
         AND Filesystem.file_path IN ("*\\Downloads\\*", "*\\Temp\\*", "*\\Desktop\\*")
     by Filesystem.dest Filesystem.user Filesystem.file_name Filesystem.file_path
     | `drop_dm_object_name(Filesystem)`
     | rename file_name as js_file_name file_path as js_file_path]
| where js_firstTime >= firstTime AND (js_firstTime - firstTime) < 300
| eval risk_score=80
| table firstTime js_firstTime dest user file_name file_path js_file_name js_file_path process_name risk_score
```

## Risk Score Logic

| Condition | Score | Rationale |
|-----------|-------|-----------|
| ZIP download followed by JS extraction within 5 min | 80 | Strong indicator of Gootloader delivery chain; legitimate ZIP+JS downloads are uncommon |

## Associated Threat Actors

| Actor | References |
|-------|-----------|
| Gootloader / UNC2565 | [MITRE - Gootloader (S1138)](https://attack.mitre.org/software/S1138/) |

## References

- [Mandiant - Tracking and Disrupting GootLoader Operations](https://www.mandiant.com/resources/tracking-and-disrupting-gootloader-operations)
- [HP Wolf Security - Gootloader Deep-Dive Analysis](https://threatresearch.ext.hp.com/gootloader-inside-out/)
