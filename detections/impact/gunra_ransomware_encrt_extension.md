# Gunra Ransomware: .ENCRT File Extension and Pre-Encryption Activity

## Description

Detects Gunra ransomware (operated by Golden Community, a Conti-derived RaaS) across three stages:

1. **Post-encryption indicators**: `.ENCRT` encrypted file extension creation and `R3ADM3.txt` ransom note drops — high-confidence late-stage indicator (risk 100)
2. **Initial access exploitation**: CVE-2024-55591 and CVE-2025-24472 Fortinet FortiOS/FortiProxy authentication bypass via WebSocket/Node.js user agent to management API endpoints (risk 90)
3. **Pre-encryption exfiltration**: Non-standard process uploading >10 MB to OneDrive/SharePoint (double-extortion stage; risk 75)

Active globally since April 2025; RaaS model launched January 2026. Linux variant has a cryptographic flaw allowing free file recovery without paying ransom. Detailed in CISA joint advisory AA26-222A (co-signed by FBI, NSA, USSS, DC3, KNPA).

**Expected false positives:**
- Query 1: Essentially none — `.ENCRT` is Gunra-specific and `R3ADM3.txt` is a direct ransomware indicator
- Query 2: Legitimate Fortinet management API calls from automation frameworks using Node.js; tune by adding known management IP sources to an allowlist
- Query 3: Legitimate large file transfers to OneDrive/SharePoint from backup or sync tools — add known backup process names to the exclusion list

## MITRE ATT&CK Mapping

- **Primary Tactic:** Impact (TA0040)
- **Secondary Tactics:** Initial Access (TA0001), Exfiltration (TA0010)
- **Techniques:**
  - T1486 — Data Encrypted for Impact (ChaCha20+RSA-4096; .ENCRT extension; R3ADM3.txt)
  - T1190 — Exploit Public-Facing Application (CVE-2024-55591, CVE-2025-24472)
  - T1567.002 — Exfiltration to Cloud Storage (main.exe → OneDrive/SharePoint)

## Lockheed Martin Kill Chain Phase

- Exploitation (CVE-2024-55591 / CVE-2025-24472 detection)
- Actions on Objectives (.ENCRT extension, R3ADM3.txt, cloud exfiltration)

## Splunk SPL Query

### Query 1: .ENCRT File Extension and R3ADM3.txt Ransom Note Creation (Risk 100)

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Endpoint.Filesystem
where Filesystem.file_name="R3ADM3.txt"
   OR match(Filesystem.file_path, "(?i)\.ENCRT$")
by Filesystem.dest Filesystem.user Filesystem.file_name Filesystem.file_path Filesystem.action
| `drop_dm_object_name(Filesystem)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=100
| table firstTime lastTime dest user file_name file_path action risk_score
```

### Query 2: CVE-2024-55591 / CVE-2025-24472 — Fortinet API Exploitation via WebSocket/Node.js UA (Risk 90)

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Web.Web
where Web.url IN ("*/api/v2/cmdb/system/admin*", "*/jsconsole*", "*node.cgi*")
  AND Web.http_method IN ("PUT","POST")
  AND Web.http_user_agent IN ("Node.js*","*websocket*")
  AND Web.status IN ("200","201","204")
by Web.src Web.dest Web.url Web.http_method Web.http_user_agent Web.status Web.user
| `drop_dm_object_name(Web)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=90
| table firstTime lastTime src dest url http_method http_user_agent status user risk_score
```

### Query 3: Pre-Encryption Exfiltration — Non-Standard Process >10 MB to OneDrive/SharePoint (Risk 75)

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Network_Traffic.All_Traffic
where (All_Traffic.dest_dns="*.sharepoint.com" OR All_Traffic.dest_dns="*.onedrive.com")
  AND All_Traffic.bytes_out > 10000000
  AND All_Traffic.process_name NOT IN ("WINWORD.exe","EXCEL.EXE","OneDrive.exe","Teams.exe","chrome.exe","firefox.exe","msedge.exe")
by All_Traffic.src All_Traffic.dest_dns All_Traffic.process_name All_Traffic.bytes_out
| `drop_dm_object_name(All_Traffic)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=75
| table firstTime lastTime src dest_dns process_name bytes_out risk_score
```

## Risk Score Logic

| Condition | Score |
|-----------|-------|
| `.ENCRT` extension created or `R3ADM3.txt` dropped | 100 |
| Fortinet management API POST/PUT with Node.js/WebSocket UA, HTTP 200-204 | 90 |
| Non-standard process uploading >10 MB to SharePoint/OneDrive | 75 |

## Associated Threat Actors

- **Golden Community** — Gunra ransomware RaaS operator; Conti-derived lineage; global targeting; active April 2025+; formal RaaS launched January 2026

## References

- [CISA Advisory AA26-222A — Gunra Ransomware (2026-08-10)](https://www.cisa.gov/news-events/cybersecurity-advisories/aa26-222a)
- [MITRE ATT&CK T1486 — Data Encrypted for Impact](https://attack.mitre.org/techniques/T1486/)
- [MITRE ATT&CK T1190 — Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/)
- [MITRE ATT&CK T1567.002 — Exfiltration to Cloud Storage](https://attack.mitre.org/techniques/T1567/002/)
- [CVE-2024-55591](https://nvd.nist.gov/vuln/detail/CVE-2024-55591)
- [CVE-2025-24472](https://nvd.nist.gov/vuln/detail/CVE-2025-24472)
