# YOOtheme Pro CVE-2026-102785 Unauthenticated RCE and Webshell Deployment

## Description

Detects exploitation of CVE-2026-102785, an unauthenticated remote code execution vulnerability in the YOOtheme Pro WordPress plugin (versions 5.0.0–5.0.52, fixed in 5.0.53). The flaw allows an attacker to reuse a legitimately signed image URL and append `FromFile=php://input` and `Save=` parameters to write a PHP webshell directly to `wp-content/uploads/`. The server returns HTTP 500 even on successful write, so a 500 status does not indicate failure.

Active exploitation was observed by Unit 42 starting approximately two days after the patch (2026-10-21). Attacks involve an automated mass scanner followed by an interactive operator deploying the ALFA Team webshell CGI kit within minutes. An attempted install of the `gsocket` remote-access tool via `curl | bash` was also observed.

**False positives:** The `yootheme=cache` query string is used legitimately by the plugin for image caching; tuning requires the presence of `FromFile=php` or `Save=wp-content/uploads/*.php` to distinguish exploitation from normal usage. Web server processes spawning shell children may also fire on legitimate server management scripts.

## MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| Tactic | Initial Access |
| Tactic ID | TA0001 |
| Technique | Exploit Public-Facing Application |
| Technique ID | T1190 |
| Secondary Techniques | T1505.003 (Web Shell), T1059 (Command and Scripting Interpreter), T1027 (Obfuscated Files), T1219 (Remote Access Software) |

## Lockheed Martin Kill Chain

| Phase |
|-------|
| Delivery |
| Exploitation |
| Installation |

## Splunk Detection Query

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Web.Web
  where Web.uri_query="*yootheme=cache*"
  AND (Web.uri_query="*FromFile=php*" OR Web.uri_query="*Save=wp-content*uploads*")
  by Web.dest Web.src Web.uri_path Web.uri_query Web.http_method Web.status Web.http_user_agent
| `drop_dm_object_name(Web)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    match(uri_query, "FromFile=php") AND match(uri_query, "Save="), 92,
    match(uri_query, "Save=wp-content"), 75,
    1=1, 55)
| where risk_score >= 75
| table firstTime lastTime dest src uri_path uri_query status http_user_agent risk_score
```

### Supplemental: Web Server Spawning Suspicious Child Processes

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Processes
  where (Processes.parent_process_name IN ("httpd","apache2","nginx","php","php-cgi","php-fpm","w3wp.exe"))
  AND (Processes.process_name IN ("cmd.exe","sh","bash","curl","wget","powershell.exe")
       OR Processes.process IN ("*echo YTS*","*gsocket*","*curl*|*bash*"))
  by Processes.dest Processes.user Processes.parent_process_name
     Processes.process_name Processes.process Processes.process_id
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    match(process, "echo YTS"), 93,
    match(process, "gsocket"), 89,
    match(process, "curl.*\|.*bash"), 87,
    process_name IN ("cmd.exe","powershell.exe"), 80,
    1=1, 70)
| where risk_score >= 70
| table firstTime lastTime dest user parent_process_name process_name process risk_score
```

## Risk Score Logic

| Condition | Score | Rationale |
|-----------|-------|-----------|
| `FromFile=php://input` AND `Save=` in yootheme query string | 92 | Direct exploitation parameters; near-certain true positive |
| `echo YTS<hex>` child of web process | 93 | Automated scanner validation beacon; highly specific pattern |
| gsocket child of web process | 89 | Remote access tool install; no legitimate web-server usage |
| `curl \| bash` child of web process | 87 | Fileless dropper pattern |
| `cmd.exe` or `powershell.exe` child of web process | 80 | Post-exploitation shell; requires analyst triage |
| `Save=wp-content/uploads` in yootheme query | 75 | PHP write attempt; lower confidence without `FromFile=php` |

## Associated Threat Actors

| Actor | References |
|-------|-----------|
| ALFA Team | Known webshell kit developer/distributor; CGI toolkit found at `wp-content/uploads/ALFA_DATA/alfacgiapi/`; long-standing underground presence |
| Unnamed automated scanner | Unit 42 Oct 26 2026 — mass exploitation; two-phase attack (scanner + interactive operator) |

## References

- Unit42 timely threat intel: https://github.com/PaloAltoNetworks/Unit42-timely-threat-intel/blob/main/2026-10-26-exploitation-of-CVE-2026-102785.txt
- NVD CVE-2026-102785: https://nvd.nist.gov/vuln/detail/CVE-2026-102785
- ENISA EUVD: https://euvd.enisa.europa.eu/vulnerability/EUVD-2026-108161
- YOOtheme changelog: https://yootheme.com/changelog
- MITRE T1190: https://attack.mitre.org/techniques/T1190/
- MITRE T1505.003: https://attack.mitre.org/techniques/T1505/003/
