# Drupal Installer Access Bypass and SQLite PHP Webshell (CVE-2026-136716)

## Description

Detects exploitation of CVE-2026-136716 (Drupal SA-CORE-2026-019, Highly Critical 21/25), which bypasses access controls on the Drupal installer interface (`install.php`/`update.php`) on production sites. Added to CISA KEV on 2026-11-27 with BOD 26-04 remediation deadline of 2026-11-30.

This detection covers three techniques:
1. POST requests to Drupal installer or updater endpoints — the entry point for exploitation
2. PHP file creation in Drupal web directories by the web server process — the SQLite-based webshell persistence technique (attacker specifies a `.php`-extension SQLite database path in the web root)
3. HTTP 200 responses to GET requests on installer endpoints — indicating the installer is accessible on a live production site (reconnaissance/exploitation precondition)

False positives: Initial Drupal deployments that have not yet completed setup will legitimately serve `install.php`. Tune by excluding known pre-production environments from the `dest` field. `CreateStoredQuery` and PHP file creation by the web server user in `sites/files/` should not occur outside deployment procedures.

## MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| Tactic | Initial Access |
| Tactic ID | TA0001 |
| Technique | Exploit Public-Facing Application |
| Technique ID | T1190 |

Secondary mapping:

| Field | Value |
|-------|-------|
| Tactic | Persistence |
| Tactic ID | TA0003 |
| Technique | Server Software Component: Web Shell |
| Technique ID | T1505.003 |

## Lockheed Martin Kill Chain

| Phase |
|-------|
| Delivery |
| Installation |

## Splunk Detection Query

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Web.Web
where Web.http_method="POST"
  AND (Web.url_path="/install.php" OR Web.url_path="/update.php"
       OR Web.url_path="/core/install.php"
       OR Web.url="*/install.php*" OR Web.url="*/update.php*"
       OR Web.url="*/core/install.php*")
by Web.src Web.dest Web.url Web.http_method Web.user_agent Web.status Web.bytes
| `drop_dm_object_name(Web)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    match(url, "install\.php") AND http_method="POST", 85,
    match(url, "update\.php") AND http_method="POST", 80,
    1=1, 70)
| where risk_score >= 70
| table firstTime lastTime src dest url http_method user_agent status risk_score
```

### Secondary Query: PHP File Creation in Drupal Web Root by Web Server Process

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Endpoint.Filesystem
where Filesystem.file_name="*.php"
  AND (Filesystem.file_path="*/sites/default/*" OR Filesystem.file_path="*/sites/files/*"
       OR Filesystem.file_path="*/public_html/*" OR Filesystem.file_path="*/drupal/*"
       OR Filesystem.file_path="*/web/*")
  AND (Filesystem.user="www-data" OR Filesystem.user="apache" OR Filesystem.user="nginx"
       OR Filesystem.user="httpd" OR Filesystem.user="php")
  AND Filesystem.action="created"
by Filesystem.dest Filesystem.user Filesystem.file_path Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    match(file_name, "\.db\.php$|\.sqlite\.php$|\.db3\.php$"), 95,
    match(file_path, "sites/default/files"), 90,
    match(file_path, "sites/files"), 85,
    1=1, 75)
| where risk_score >= 75
| table firstTime lastTime dest user file_path file_name risk_score
```

## Risk Score Logic

| Condition | Score | Rationale |
|-----------|-------|-----------|
| `.db.php` or `.sqlite.php` extension file created by web process | 95 | Direct SQLite-webshell persistence indicator from CVE-2026-136716 technique |
| PHP file created in `sites/default/files` by web server | 90 | Web-server-writable directory; PHP file here executes as webshell and is not part of Drupal core |
| POST to `install.php` on production site | 85 | Installer should not accept POST requests on live Drupal deployments |
| POST to `update.php` on production site | 80 | Updater requires admin login; POST without valid session is exploitation attempt |

## Associated Threat Actors

| Actor | References |
|-------|-----------|
| Unknown opportunistic actors (November 2026) | [CISA KEV 2026-11-27](https://www.cisa.gov/news-events/alerts/2026/11/27/cisa-adds-three-known-exploited-vulnerabilities-catalog), [Drupal SA-CORE-2026-019](https://www.drupal.org/sa-core-2026-019) |
| CSIRT-Italia reported active exploitation | [SecurityWeek 2026-11-27](https://www.securityweek.com/drupal-installer-patch-left-a-gap-attackers-are-already-exploiting/) |

## References

- [Drupal SA-CORE-2026-019 (CVE-2026-136716)](https://www.drupal.org/sa-core-2026-019)
- [CISA KEV Alert 2026-11-27](https://www.cisa.gov/news-events/alerts/2026/11/27/cisa-adds-three-known-exploited-vulnerabilities-catalog)
- [SecurityWeek — Drupal Installer Patch Left a Gap](https://www.securityweek.com/drupal-installer-patch-left-a-gap-attackers-are-already-exploiting/)
- [MITRE ATT&CK T1190 — Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/)
- [MITRE ATT&CK T1505.003 — Server Software Component: Web Shell](https://attack.mitre.org/techniques/T1505/003/)
- [Threat Intel Report](../../threat-intel/2026-11-28_drupal-core-cve-2026-136716-installer-access-bypass-site-takeover.md)
