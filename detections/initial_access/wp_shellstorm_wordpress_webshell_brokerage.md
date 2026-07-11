# WP-SHELLSTORM WordPress Webshell Brokerage

## Description

Detects activity associated with WP-SHELLSTORM, a webshell access brokerage operation discovered by SOCRadar in June 2026. The actor exploits 27 CVEs across WordPress and Joomla plugins to mass-compromise websites and resell webshell access to downstream buyers. The primary exploit vector is CVE-2026-3844 (WordPress Breeze Cache Plugin, CVSS 9.8 unauthenticated arbitrary file upload). Over 5,700 sites were compromised and 1.4M+ domains targeted.

Webshells use distinctive naming conventions: leading-dot filenames (`.bd.php`, `.wp-log.php`, `.nf-log.php`, `.sd.php`) to hide from standard directory listings, randomized-suffix variants (`.brq-*.php`, `.leo_*.php`, `.wvp-*.php`, `.cc-*.php`), and `.phtml` extension variants (`BZ_*.phtml`) to bypass `.php` extension blocking. The primary backdoor (`down.php`) is a 4-layer obfuscated PHP webshell derived from the open-source Chinese BestShell codebase.

**False positives:** Legitimate hidden PHP files (`.htaccess.php`) or `BZ_` prefixed backup files on managed WordPress hosts are uncommon but possible. Validate by checking file content and correlating with web access logs. The C2 IP (`137.175.93.126`) has no legitimate use and should have zero expected traffic.

## MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| Tactic | Initial Access, Persistence |
| Tactic ID | TA0001, TA0003 |
| Technique | Exploit Public-Facing Application; Server Software Component: Web Shell |
| Technique ID | T1190; T1505.003 |

## Lockheed Martin Kill Chain

| Phase |
|-------|
| Exploitation |
| Installation |

## Splunk Detection Query

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Web.Web
where (Web.uri="*/.bd.php" OR Web.uri="*/.wp-log.php" OR Web.uri="*/.nf-log.php"
  OR Web.uri="*/.sd.php" OR Web.uri LIKE "*/.brq-%.php"
  OR Web.uri LIKE "*/.leo_%.php" OR Web.uri LIKE "*/.wvp-%.php"
  OR Web.uri LIKE "*/.cc-%.php" OR Web.uri LIKE "*/BZ_%.phtml")
by Web.src Web.dest Web.uri Web.http_user_agent Web.status Web.http_method
| `drop_dm_object_name(Web)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    (uri="*/.bd.php" OR uri="*/.wp-log.php" OR uri="*/.nf-log.php"), 90,
    (uri LIKE "*/BZ_%.phtml"), 85,
    1=1, 80)
| where risk_score >= 80
| table firstTime lastTime src dest uri status http_method risk_score
```

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Endpoint.Filesystem
where (Filesystem.file_name=".bd.php" OR Filesystem.file_name=".wp-log.php"
  OR Filesystem.file_name=".nf-log.php" OR Filesystem.file_name=".sd.php"
  OR Filesystem.file_name LIKE ".brq-%.php" OR Filesystem.file_name LIKE ".leo_%.php"
  OR Filesystem.file_name LIKE ".wvp-%.php" OR Filesystem.file_name LIKE ".cc-%.php"
  OR Filesystem.file_name LIKE "BZ_%.phtml")
  AND (Filesystem.file_path="*/wp-content/*" OR Filesystem.file_path="*/public_html/*"
    OR Filesystem.file_path="*/htdocs/*" OR Filesystem.file_path="*/www/*"
    OR Filesystem.file_path="*/html/*")
by Filesystem.dest Filesystem.user Filesystem.file_name Filesystem.file_path Filesystem.action
| `drop_dm_object_name(Filesystem)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=90
| where risk_score >= 90
| table firstTime lastTime dest user file_name file_path action risk_score
```

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Network_Traffic.All_Traffic
where All_Traffic.dest="137.175.93.126"
by All_Traffic.src All_Traffic.dest All_Traffic.dest_port All_Traffic.action
| `drop_dm_object_name(All_Traffic)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=95
| table firstTime lastTime src dest dest_port action risk_score
```

## Risk Score Logic

| Condition | Score | Rationale |
|-----------|-------|-----------|
| Web request to `.bd.php`, `.wp-log.php`, or `.nf-log.php` | 90 | Highest-confidence WP-SHELLSTORM webshell filenames; no legitimate use on web servers |
| Web request to `BZ_*.phtml` | 85 | WP-SHELLSTORM `.phtml` webshell variant; uncommon in legitimate WordPress deployments |
| Web request to other WP-SHELLSTORM filename patterns | 80 | Randomized-suffix variants; less specific but still high-confidence indicators |
| Webshell file creation in web root directories | 90 | File creation event confirms compromise; Filesystem events are high fidelity |
| Network connection to `137.175.93.126` | 95 | WP-SHELLSTORM operator C2 server; any connection is a near-certain true positive |

## Associated Threat Actors

| Actor | References |
|-------|-----------|
| Unknown (WP-SHELLSTORM operator, June 2026) | [SOCRadar — WP-SHELLSTORM](https://socradar.io/blog/wp-shellstorm-expose-1-4m-wordpress-sites/) |

## References

- [SOCRadar — WP-SHELLSTORM: Exposing 1.4M WordPress Sites](https://socradar.io/blog/wp-shellstorm-expose-1-4m-wordpress-sites/)
- [NVD CVE-2026-3844 — Breeze Cache Plugin Unauthenticated File Upload](https://nvd.nist.gov/vuln/detail/CVE-2026-3844)
- [MITRE ATT&CK T1190 — Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/)
- [MITRE ATT&CK T1505.003 — Server Software Component: Web Shell](https://attack.mitre.org/techniques/T1505/003/)
