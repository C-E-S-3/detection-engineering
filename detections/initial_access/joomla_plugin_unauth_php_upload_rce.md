# Joomla Plugin Unauthenticated PHP Upload RCE (CVE-2026-48908 / CVE-2026-56290)

## Description

Detects unauthenticated PHP web shell upload via vulnerable Joomla plugin file upload endpoints. Two critical vulnerabilities (CVSS 10.0) in the Joomla plugin ecosystem were added to the CISA KEV on July 7, 2026, following confirmation of active exploitation:

- **CVE-2026-48908**: JoomShaper SP Page Builder ≤6.6.1 — the `asset.uploadCustomIcon` task requires no authentication and performs no file-type validation, allowing any attacker to upload a PHP webshell in a single unauthenticated POST request. Post-exploitation activity includes rogue Joomla Super Administrator account creation with `*@secure.local` email addresses.

- **CVE-2026-56290**: Joomlack Page Builder CK ≤3.6.0 — the upload endpoint's only protection is a Joomla CSRF token that is readable from the site's HTML by any visitor, making it effectively unauthenticated.

Both follow the same exploitation template as CVE-2026-48907 (Joomla JCE, CISA KEV June 16, 2026), indicating systematic pressure on the Joomla plugin ecosystem in 2026. A public PoC for CVE-2026-48908 is available on GitHub.

False positives: Legitimate Joomla file uploads via these components will not typically result in PHP files in the media directories; filter by file extension to reduce noise.

## MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| Tactic | Initial Access |
| Tactic ID | TA0001 |
| Technique | Exploit Public-Facing Application |
| Technique ID | T1190 |
| Secondary Tactic | Persistence |
| Secondary Tactic ID | TA0003 |
| Secondary Technique | Server Software Component: Web Shell |
| Secondary Technique ID | T1505.003 |

## Lockheed Martin Kill Chain

| Phase |
|-------|
| Exploitation |
| Installation |

## Splunk Detection Query

**Query 1 — Unauthenticated POST to vulnerable upload endpoints:**

```spl
`web` method=POST (uri="*com_sppagebuilder*task=asset.uploadCustomIcon*" OR uri="*com_ckpagebuilder*upload*")
| eval risk_score=case(
    match(uri, "uploadCustomIcon"), 90,
    1=1, 85)
| eval detection="Joomla_Plugin_Unauth_File_Upload_CVE_2026_48908_CVE_2026_56290"
| where risk_score >= 85
| table _time, src_ip, dest, uri, status, risk_score, detection
```

**Query 2 — PHP web shell drop in Joomla media directories:**

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Filesystem
  where Filesystem.file_path IN ("*/media/com_sppagebuilder/assets/iconfont/*/fonts/*.php*",
                                  "*/media/com_ckpagebuilder/*/*.php*",
                                  "*/images/stories/*.php*")
    AND Filesystem.file_name IN ("*.php","*.PHP","*.pHP","*.pHp","*.Php")
  by Filesystem.dest Filesystem.user Filesystem.file_path Filesystem.file_name Filesystem.process_name
| `drop_dm_object_name(Filesystem)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=95
| eval detection="Joomla_PHP_Webshell_Drop_Media_Dir"
| table firstTime lastTime dest user file_path file_name process_name risk_score detection
```

**Query 3 — Rogue Joomla Super Administrator account creation:**

```spl
index=* sourcetype IN ("joomla","joomla_access") action="create_user"
(email="*@secure.local" OR username IN ("webeditor*","siteeditor*","webmaster*","admin*","siteadmin*"))
| eval risk_score=90
| eval detection="Joomla_Rogue_SuperAdmin_Account_CVE_2026_48908"
| table _time, host, action, email, username, risk_score, detection
```

**Query 4 — Web server process spawning shell children (post-exploitation):**

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Processes
  where Processes.parent_process_name IN ("httpd","apache2","nginx","php-fpm","w3wp.exe")
    AND Processes.process_name IN ("cmd.exe","sh","bash","powershell.exe","whoami","id","curl","wget","python*","perl","nc","ncat")
  by Processes.dest Processes.user Processes.parent_process_name Processes.process_name Processes.process
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=85
| where risk_score >= 85
| table firstTime lastTime dest user parent_process_name process_name process risk_score
```

## Risk Score Logic

| Condition | Score | Rationale |
|-----------|-------|-----------|
| POST to `uploadCustomIcon` endpoint (CVE-2026-48908) | 90 | Exploitation-specific endpoint with no legitimate unauthenticated use |
| POST to Joomlack CK upload endpoint (CVE-2026-56290) | 85 | CSRF-bypass upload; any visitor can exploit |
| PHP file written to Joomla media directory | 95 | PHP files have no legitimate purpose in font/icon media directories |
| Rogue `@secure.local` Joomla admin created | 90 | Post-exploitation indicator specific to CVE-2026-48908 campaign |
| Web server spawning interactive shell | 85 | Webshell command execution; very low false positive rate in production environments |

## Associated Threat Actors

| Actor | References |
|-------|-----------|
| Unknown opportunistic actors (CVE-2026-48908 campaign, July 2026) | [CISA KEV July 7, 2026](https://www.cisa.gov/news-events/alerts/2026/07/07/cisa-adds-three-known-exploited-vulnerabilities-catalog), [PoC — CVE-2026-48908](https://github.com/papageo75/CVE-2026-48908-PoC) |
| Unknown opportunistic actors (CVE-2026-56290 campaign, July 2026) | [CCB Belgium Advisory — CVE-2026-56290](https://ccb.belgium.be/advisories/warning-critical-unauthenticated-arbitrary-file-upload-vulnerability-cve-2026-56290) |

## References

- [CISA KEV Alert — July 7, 2026](https://www.cisa.gov/news-events/alerts/2026/07/07/cisa-adds-three-known-exploited-vulnerabilities-catalog)
- [Censys Advisory — CVE-2026-48908](https://censys.com/advisory/cve-2026-48908/)
- [mySites.guru — SP Page Builder Zero Day Writeup](https://mysites.guru/blog/sp-page-builder-zero-day-uploadcustomicon-rce/)
- [SecurityAffairs — CISA KEV Joomlack / SP Page Builder](https://securityaffairs.com/194927/hacking/u-s-cisa-adds-adobe-coldfusion-joomlack-page-builder-langflow-and-joomshaper-sp-page-builder-flaws-to-its-known-exploited-vulnerabilities-catalog.html)
- [CCB Belgium Advisory — CVE-2026-56290](https://ccb.belgium.be/advisories/warning-critical-unauthenticated-arbitrary-file-upload-vulnerability-cve-2026-56290)
- [GitHub PoC — CVE-2026-48908](https://github.com/papageo75/CVE-2026-48908-PoC)
- [NVD — CVE-2026-48908](https://nvd.nist.gov/vuln/detail/CVE-2026-48908)
- [MITRE ATT&CK T1190 — Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/)
- [MITRE ATT&CK T1505.003 — Web Shell](https://attack.mitre.org/techniques/T1505/003/)
