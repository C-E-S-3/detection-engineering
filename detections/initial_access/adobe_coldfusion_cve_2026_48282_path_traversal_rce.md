# Adobe ColdFusion APSB26-68 Path Traversal RCE (CVE-2026-48282)

## Description

Detects active exploitation of CVE-2026-48282, a CVSS 10.0 path traversal vulnerability in Adobe ColdFusion 2023/2025 confirmed exploited in the wild within hours of public disclosure (July 1, 2026). APSB26-68 also patches six additional CVSS 10.0 flaws including unrestricted file upload (CVE-2026-48276, CVE-2026-48283) that enable webshell deployment without authentication.

Detection covers two surfaces:
1. **Web layer** — Path traversal sequences in HTTP requests to ColdFusion endpoints
2. **Endpoint layer** — ColdFusion JVM or web process spawning unexpected child processes (post-exploitation indicator)

False positives are expected from legitimate path-based routing in ColdFusion applications for the web detection. The endpoint-layer detection (ColdFusion spawning shells) has very low expected false positive rate in production environments.

## MITRE ATT&CK Mapping

| Tactic | Tactic ID | Technique | Technique ID |
|--------|-----------|-----------|--------------|
| Initial Access | TA0001 | Exploit Public-Facing Application | T1190 |
| Persistence | TA0003 | Server Software Component: Web Shell | T1505.003 |

## Lockheed Martin Kill Chain

| Phase |
|-------|
| Delivery |
| Exploitation |
| Installation (webshell via CVE-2026-48276/48283) |

## Splunk Detection Query

**Query 1 — Web Layer: Path Traversal Patterns in ColdFusion Requests**

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Web.Web
where Web.dest_port IN (80, 443, 8500, 8501)
  AND (Web.uri_path LIKE "%../%"
       OR Web.uri_path LIKE "%..\\%"
       OR Web.uri_path LIKE "%2e2e%"
       OR Web.uri_path LIKE "%252e252e%"
       OR Web.uri_query LIKE "%../%" 
       OR Web.uri_query LIKE "%..\\%")
  AND (Web.dest="*coldfusion*"
       OR Web.uri_path LIKE "%/CFIDE/%"
       OR Web.uri_path LIKE "%/cfide/%"
       OR Web.dest_port IN (8500, 8501))
by Web.src Web.dest Web.dest_port Web.uri_path Web.uri_query Web.http_method Web.status
| `drop_dm_object_name(Web)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    match(uri_path,"(?i)(win\.ini|etc/passwd|boot\.ini|system32)"), 90,
    match(uri_path,"(?i)(\.\./|\.\.\\\|%2e%2e|%252e)"), 75,
    1=1, 50)
| where risk_score >= 50
| table firstTime lastTime src dest dest_port http_method uri_path uri_query status risk_score
```

**Query 2 — Endpoint Layer: ColdFusion Spawning Shell Processes**

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Endpoint.Processes
where Processes.parent_process_name IN ("cfusion.exe","jvm.exe","java.exe","javaw.exe")
  AND Processes.process_name IN ("cmd.exe","powershell.exe","wscript.exe","cscript.exe",
      "mshta.exe","certutil.exe","bitsadmin.exe","rundll32.exe","regsvr32.exe",
      "net.exe","net1.exe","whoami.exe","ipconfig.exe","nslookup.exe","ping.exe")
by Processes.dest Processes.user Processes.parent_process_name
   Processes.process_name Processes.process Processes.process_id
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    match(process_name,"(?i)(powershell|mshta|wscript|cscript|certutil|bitsadmin)"), 90,
    match(process_name,"(?i)(cmd\.exe)") AND match(process,"(?i)(/c |/k )"), 85,
    1=1, 70)
| where risk_score >= 70
| table firstTime lastTime dest user parent_process_name process_name process risk_score
```

**Query 3 — Endpoint Layer: Webshell File Creation in ColdFusion Web Root**

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Endpoint.Filesystem
where Filesystem.file_name IN ("*.cfm","*.jsp","*.jspf","*.cfmail","*.war","*.aspx","*.ashx","*.asmx","*.php")
  AND (Filesystem.file_path LIKE "*\\ColdFusion*\\wwwroot\\*"
       OR Filesystem.file_path LIKE "*\\ColdFusion*\\cfide\\*"
       OR Filesystem.file_path LIKE "*/coldfusion*/wwwroot/*"
       OR Filesystem.file_path LIKE "*/coldfusion*/cfide/*")
  AND Filesystem.action="created"
  AND Filesystem.process_name NOT IN ("cfusion.exe","jvm.exe","cfupdate.exe","adobeupdater.exe")
by Filesystem.dest Filesystem.user Filesystem.file_name Filesystem.file_path Filesystem.process_name
| `drop_dm_object_name(Filesystem)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=90
| table firstTime lastTime dest user process_name file_name file_path risk_score
```

## Risk Score Logic

| Condition | Score | Rationale |
|-----------|-------|-----------|
| Path traversal targeting known sensitive files (`win.ini`, `passwd`, `boot.ini`) | 90 | High-confidence exploitation attempt with confirmed canary files |
| Path traversal patterns in ColdFusion URI paths | 75 | Likely CVE-2026-48282 exploitation probe |
| ColdFusion parent spawning PowerShell, mshta, wscript, or certutil | 90 | Near-certain post-exploitation; no legitimate operational reason |
| ColdFusion parent spawning cmd.exe with `/c` or `/k` arguments | 85 | Strong post-exploitation indicator |
| ColdFusion parent spawning other common shell utilities | 70 | Suspicious; warrants investigation |
| Unknown process creating `.cfm`, `.jspf`, `.cfmail`, or `.war` in ColdFusion web root | 90 | Webshell deployment via CVE-2026-48276/48283 unrestricted upload |
| General path traversal pattern in ColdFusion-bound traffic | 50 | Investigate; may be legitimate URL-encoded paths |

## Associated Threat Actors

| Actor | References |
|-------|-----------|
| Unknown opportunistic actors (CVE-2026-48282 exploiters, July 2026) | Single exploitation attempt from `103.207.14[.]220` (India-geolocated) recorded within hours of disclosure; file-read probe targeting `C:\Windows\win.ini`; [BleepingComputer — APSB26-68 (2026-07-01)](https://www.bleepingcomputer.com/news/security/adobe-patches-seven-max-severity-coldfusion-campaign-flaws/) |
| Cl0p Ransomware / Ransomware Affiliates | Historical ColdFusion exploitation pattern; managed file-transfer platform targeting; [BleepingComputer — Cl0p ShareFile](https://www.bleepingcomputer.com/news/security/new-progress-sharefile-flaws-can-be-chained-in-pre-auth-rce-attacks/) |

## References

- [Adobe APSB26-68 — Security Bulletin](https://helpx.adobe.com/security/products/coldfusion/apsb26-68.html)
- [BleepingComputer — Adobe Patches Seven Max Severity ColdFusion, Campaign Flaws (2026-07-01)](https://www.bleepingcomputer.com/news/security/adobe-patches-seven-max-severity-coldfusion-campaign-flaws/)
- [SecurityWeek — Adobe Patches Critical ColdFusion, Campaign Classic Vulnerabilities](https://www.securityweek.com/adobe-patches-critical-coldfusion-campaign-classic-vulnerabilities/)
- [WatchTowr Labs — ColdFusion APSB26-68 Technical Analysis](https://labs.watchtowr.com/its-37oc-and-all-we-can-think-about-is-coldfusion-adobe-coldfusion-security-bulletin-apsb26-68-cve-bonanza/)
- [Qualys ThreatPROTECT — Adobe ColdFusion Critical Vulnerabilities (2026-07-01)](https://threatprotect.qualys.com/2026/07/01/adobe-releases-patches-for-coldfusion-critical-vulnerabilities/)
- [MITRE ATT&CK — T1190: Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/)
- [MITRE ATT&CK — T1505.003: Web Shell](https://attack.mitre.org/techniques/T1505/003/)
- [NVD — CVE-2026-48282](https://nvd.nist.gov/vuln/detail/CVE-2026-48282)
- [NVD — CVE-2026-48276](https://nvd.nist.gov/vuln/detail/CVE-2026-48276)
