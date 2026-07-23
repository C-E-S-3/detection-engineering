# SharePoint CVE-2026-50522 WS-Federation Deserialization RCE — Machine Key Theft and Token Forgery

## Description

Detects exploitation of CVE-2026-50522, a CWE-502 deserialization vulnerability (CVSS 9.8) in Microsoft SharePoint Server (Subscription Edition, 2019, Enterprise Server 2016). An unauthenticated attacker sends an HTTP POST to SharePoint's WS-Federation passive requester endpoint (`/_trust/default.aspx`) containing a malicious `.NET BinaryFormatter` gadget chain embedded in the `SecurityContextToken` cookie. SharePoint deserializes the cookie without validating the token against a trusted Identity Provider signature, achieving remote code execution as the `w3wp.exe` IIS worker process.

Post-exploitation, attackers issue a single targeted request to retrieve the SharePoint machine key from the application's web.config. The machine key is used to cryptographically sign and encrypt SharePoint authentication tokens, ViewState, and session cookies. With the machine key, an attacker can forge valid authentication tokens for any SharePoint user (including farm administrators) without credentials. **Patching CVE-2026-50522 does not invalidate stolen machine keys** — token forgery remains possible until the machine key is explicitly rotated across the SharePoint farm.

This vulnerability is distinct from CVE-2026-45659 (Site Member–authenticated deserialization via SharePoint REST API, CVSS 8.8) and CVE-2026-56164 (unauthenticated network access to a critical function, CVSS 5.3). Public PoC was released July 20, 2026; active exploitation confirmed by watchTowr honeypot telemetry within hours of PoC publication.

False positives for Query 1 (POST to `/_trust/default.aspx`): federated SharePoint deployments receive legitimate WS-Federation POST requests from trusted Identity Providers — tune by restricting the source IP space to known external ranges and focusing on unauthenticated (`cs_username = "-"`) requests. False positives for Query 2 (w3wp.exe child processes): SharePoint Timer Jobs and third-party integrations occasionally spawn cmd.exe; baseline process ancestry in your environment before alerting.

## MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| Primary Tactic | Initial Access |
| Primary Tactic ID | TA0001 |
| Primary Technique | Exploit Public-Facing Application |
| Primary Technique ID | T1190 |
| Secondary Tactic | Credential Access |
| Secondary Tactic ID | TA0006 |
| Secondary Technique | Unsecured Credentials: Private Keys |
| Secondary Technique ID | T1552.004 |
| Tertiary Tactic | Persistence |
| Tertiary Tactic ID | TA0003 |
| Tertiary Technique | Use Alternate Authentication Material: Application Access Token |
| Tertiary Technique ID | T1550.001 |

## Lockheed Martin Kill Chain

| Phase |
|-------|
| Delivery |
| Exploitation |
| Actions on Objectives (machine key theft for persistent access) |

## Splunk Detection Query

### Query 1: Unauthenticated POST to WS-Federation Endpoint (Exploit Delivery)

```spl
index=iis sourcetype=iis
    cs_uri_stem="*/_trust/default.aspx*"
    cs_method=POST
| eval is_authenticated=if(cs_username="-", "no", "yes")
| stats
    count as post_count
    sum(cs_bytes) as total_bytes_in
    values(sc_status) as response_codes
    values(cs_uri_stem) as endpoints
    min(_time) as firstTime
    max(_time) as lastTime
    by c_ip cs_username s_computername is_authenticated
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    is_authenticated="no" AND mvfind(response_codes, "200|302|500") >= 0, 90,
    is_authenticated="no", 80,
    1=1, 60)
| where risk_score >= 60
| table firstTime lastTime s_computername c_ip cs_username is_authenticated post_count total_bytes_in response_codes endpoints risk_score
```

### Query 2: IIS Worker Process Spawning Child Processes Post-Exploitation

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Endpoint.Processes
where Processes.parent_process_name="w3wp.exe"
  AND (Processes.process_name IN ("cmd.exe","powershell.exe","pwsh.exe","csc.exe",
    "certutil.exe","bitsadmin.exe","mshta.exe","wscript.exe","cscript.exe",
    "rundll32.exe","regsvr32.exe","msiexec.exe","wmic.exe","net.exe",
    "net1.exe","whoami.exe","ipconfig.exe","nltest.exe","nslookup.exe"))
by Processes.dest Processes.user Processes.parent_process_name
   Processes.parent_process_id Processes.process_name Processes.process Processes.process_id
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    match(process_name,"(?i)(powershell|pwsh|csc)\.exe"), 90,
    match(process_name,"(?i)(certutil|bitsadmin|mshta|wscript|cscript)\.exe"), 85,
    match(process_name,"(?i)(rundll32|regsvr32|msiexec|wmic)\.exe"), 80,
    1=1, 70)
| where risk_score >= 70
| table firstTime lastTime dest user parent_process_name process_name process process_id risk_score
```

### Query 3: Webshell Written to SharePoint Web Root by IIS Worker

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Endpoint.Filesystem
where Filesystem.process_name="w3wp.exe"
  AND (Filesystem.file_name="*.aspx" OR Filesystem.file_name="*.asmx"
       OR Filesystem.file_name="*.ashx" OR Filesystem.file_name="*.asp")
  AND (Filesystem.file_path="*\\inetpub\\wwwroot\\wss\\*"
       OR Filesystem.file_path="*\\SharePoint\\*"
       OR Filesystem.file_path="*\\_trust\\*"
       OR Filesystem.file_path="*\\_layouts\\*")
by Filesystem.dest Filesystem.user Filesystem.process_name
   Filesystem.file_name Filesystem.file_path Filesystem.action
| `drop_dm_object_name(Filesystem)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=95
| table firstTime lastTime dest user process_name file_name file_path action risk_score
```

### Query 4: web.config Accessed by Non-IIS Process (Machine Key Exfiltration)

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Endpoint.Filesystem
where Filesystem.file_name="web.config"
  AND NOT Filesystem.process_name IN ("w3wp.exe","svchost.exe","msiexec.exe",
    "wsstracing.exe","OWSTIMER.EXE","SPTimerV4.exe","SPUCWorkerProcess.exe",
    "iissetup.exe","aspnet_compiler.exe","devenv.exe")
by Filesystem.dest Filesystem.user Filesystem.process_name Filesystem.file_path Filesystem.action
| `drop_dm_object_name(Filesystem)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=80
| where risk_score >= 80
| table firstTime lastTime dest user process_name file_path action risk_score
```

## Risk Score Logic

| Condition | Score | Rationale |
|-----------|-------|-----------|
| Webshell (.aspx/.ashx/.asmx) written by w3wp.exe to SharePoint web root | 95 | Near-certain webshell persistence post-CVE-2026-50522 exploitation |
| w3wp.exe spawning PowerShell/pwsh/csc.exe | 90 | .NET compilation or PowerShell download cradle after deserialization RCE |
| Unauthenticated POST to `/_trust/default.aspx` returning 200/302/500 | 90 | Exploit delivery to WS-Federation endpoint; 500 often indicates deserialization attempt |
| Unauthenticated POST to `/_trust/default.aspx` (any status) | 80 | Anomalous WS-Federation usage; tune with source IP allowlisting for trusted IdPs |
| w3wp.exe spawning certutil/bitsadmin/mshta | 85 | Download-and-execute LOLBin; staged payload after initial code execution |
| w3wp.exe spawning rundll32/regsvr32/msiexec/wmic | 80 | Payload loading or persistence post-exploitation |
| web.config accessed by non-IIS process | 80 | Targeted machine key exfiltration; expected process exclusion list is narrow |
| w3wp.exe spawning whoami/ipconfig/nltest/nslookup | 70 | Post-exploit reconnaissance enumeration |

## Associated Threat Actors

| Actor | References |
|-------|-----------|
| Unknown — exploitation confirmed within hours of July 20, 2026 PoC release | [watchTowr Honeypot Telemetry (2026-07-21)](https://watchtowrcyber.com/) |
| Nation-state APT groups (SharePoint targeted for document/intelligence collection) | [MITRE ATT&CK — T1190](https://attack.mitre.org/techniques/T1190/) |
| Ransomware affiliates (SharePoint as initial access staging target) | [BleepingComputer — SharePoint targeting](https://www.bleepingcomputer.com/tag/sharepoint/) |

## References

- [Threat Intel Report — CVE-2026-50522 SharePoint Machine Key Theft (2026-07-22)](../../threat-intel/2026-07-22_bleepingcomputer-cve-2026-50522-sharepoint-machine-key-theft.md)
- [Microsoft Security Update Guide — July 2026 Patch Tuesday](https://msrc.microsoft.com/update-guide/)
- [MITRE ATT&CK — T1190: Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/)
- [MITRE ATT&CK — T1552.004: Unsecured Credentials: Private Keys](https://attack.mitre.org/techniques/T1552/004/)
- [MITRE ATT&CK — T1550.001: Use Alternate Authentication Material: Application Access Token](https://attack.mitre.org/techniques/T1550/001/)
- [CWE-502 — Deserialization of Untrusted Data](https://cwe.mitre.org/data/definitions/502.html)
