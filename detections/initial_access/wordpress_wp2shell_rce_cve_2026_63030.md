# WordPress Core wp2shell Pre-Auth RCE (CVE-2026-63030 / CVE-2026-60137)

## Description

Detects exploitation of the wp2shell attack chain against WordPress Core — a two-vulnerability combination that achieves unauthenticated remote code execution on default WordPress installs with no plugins required.

**CVE-2026-63030** (CVSS 9.8) is a REST API batch-route permission desynchronization flaw introduced in WordPress 6.9. The `/wp-json/batch/v1` endpoint processes an array of sub-requests; when the first sub-request path is an unparseable URL (e.g., `http://:`), it is recorded in the error list but skipped in the validation matches list, causing subsequent sub-requests to be evaluated against the wrong permission callback. This allows an unauthenticated caller to invoke REST API handlers that require authentication.

**CVE-2026-60137** is an SQL injection vulnerability in the `author__not_in` parameter of the WordPress `WP_Query` class, accessible via the REST API. Chained with CVE-2026-63030, an unauthenticated attacker can extract password hashes for all WordPress users from the database.

**Public PoC exploit flow (July 18, 2026):**
1. POST malformed batch request to `/wp-json/batch/v1` to trigger permission desync
2. Inject SQL via `author__not_in` parameter to extract admin password hash
3. Crack hash offline, authenticate as admin
4. Upload malicious PHP plugin ZIP via `/wp-admin/update.php?action=upload-plugin`
5. Activate plugin → arbitrary PHP code execution as web server user

An alternative PoC path claims direct pre-auth RCE without hash cracking, exploiting only the batch permission bypass.

Affected: WordPress 6.9.0–6.9.4 and 7.0.0–7.0.1. The SQL injection (CVE-2026-60137) also affects 6.8.0–6.8.5 but cannot chain to RCE in those versions because the batch endpoint bug was introduced in 6.9. The code-execution path requires no persistent object cache (default configuration). Patched in 6.9.5 and 7.0.2.

**False positive sources:** Legitimate REST API clients POSTing to `/wp-json/batch/v1`; automated WordPress health checks; security scanners performing recon; plugin upload during routine WordPress maintenance. Tune by allowlisting known admin source IPs and expected maintenance windows.

## MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| Tactic | Initial Access |
| Tactic ID | TA0001 |
| Technique | Exploit Public-Facing Application |
| Technique ID | T1190 |

Secondary techniques: T1505.003 (Server Software Component: Web Shell — PHP plugin webshell persistence), T1059.004 (Command and Scripting Interpreter: Unix Shell — post-webshell command execution), T1078.003 (Valid Accounts: Local Accounts — cracked WordPress admin credentials used)

## Lockheed Martin Kill Chain

| Phase |
|-------|
| Exploitation |
| Installation |

## Splunk Detection Query

**Query 1 — REST API Batch Endpoint Exploitation Probe**

Detects POST requests to the WordPress batch REST API endpoint. The `http://:` malformed-URL fingerprint in the body would appear in full packet-capture data models; without packet inspection, the endpoint access itself is the primary indicator.

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Web.Web
  where Web.http_method="POST"
    AND (Web.url="*/wp-json/batch/v1*" OR Web.url="*rest_route=%2Fbatch%2Fv1*"
         OR Web.url="*rest_route=/batch/v1*")
  by Web.dest Web.src Web.url Web.http_method Web.status Web.http_user_agent Web.bytes_in
| `drop_dm_object_name(Web)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    status IN ("200","201") AND bytes_in > 200, 90,
    status IN ("200","201"), 80,
    status IN ("400","403","422"), 65,
    1=1, 60)
| where risk_score >= 65
| table firstTime lastTime dest src url http_method status bytes_in http_user_agent risk_score
```

**Query 2 — WordPress REST API SQL Injection via author__not_in**

Detects SQL injection probe patterns in WordPress REST API query parameters matching the CVE-2026-60137 attack surface. Requires access to HTTP request body or query string (proxy/WAF log source with full query string capture).

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Web.Web
  where Web.url="*/wp-json/wp/v2*"
    AND (Web.url="*author__not_in*" OR Web.url="*author_not_in*")
    AND (Web.url="*SELECT*" OR Web.url="*UNION*" OR Web.url="*0x*"
         OR Web.url="*%27*" OR Web.url="*%22*" OR Web.url="*SLEEP*"
         OR Web.url="*BENCHMARK*" OR Web.url="*information_schema*")
  by Web.dest Web.src Web.url Web.http_method Web.status Web.http_user_agent
| `drop_dm_object_name(Web)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    match(url, "(?i)UNION.+SELECT|SELECT.+FROM"), 95,
    match(url, "(?i)information_schema|sleep\(|benchmark\("), 90,
    1=1, 80)
| where risk_score >= 80
| table firstTime lastTime dest src url http_method status http_user_agent risk_score
```

**Query 3 — WordPress Plugin Upload Post-Exploitation**

Detects plugin ZIP upload to the WordPress admin panel from unexpected sources, a step in the wp2shell post-exploitation chain following admin credential compromise.

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Web.Web
  where Web.http_method="POST"
    AND (Web.url="*/wp-admin/update.php*" OR Web.url="*/wp-admin/plugin-install.php*"
         OR Web.url="*/wp-admin/admin-ajax.php*")
    AND Web.status IN ("200","302")
    AND Web.bytes_in > 10000
  by Web.dest Web.src Web.url Web.http_method Web.status Web.bytes_in Web.http_user_agent
| `drop_dm_object_name(Web)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    match(url, "(?i)update\.php") AND match(url, "(?i)action=upload-plugin"), 90,
    match(url, "(?i)update\.php|plugin-install\.php") AND bytes_in > 50000, 85,
    match(http_user_agent, "(?i)python|curl|wget|go-http|java|libwww"), 85,
    1=1, 70)
| where risk_score >= 85
| table firstTime lastTime dest src url http_method status bytes_in http_user_agent risk_score
```

**Query 4 — PHP Webshell Execution: Web Process Spawning Shell Commands (Linux)**

Detects PHP-FPM, Apache, or nginx spawning unexpected child processes — the indicator of active webshell execution post-wp2shell compromise. Primary detection path for post-installation activity.

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Processes
  where Processes.parent_process_name IN ("php-fpm","php-fpm7.4","php-fpm8.0","php-fpm8.1",
      "php-fpm8.2","php-fpm8.3","php","apache2","httpd","nginx")
    AND Processes.process_name IN ("bash","sh","dash","ksh","zsh","python","python3",
        "perl","ruby","curl","wget","nc","ncat","netcat","socat","id","whoami",
        "uname","hostname","ifconfig","ip","awk","sed","find","cat","ls","cp","mv",
        "chmod","chown","tar","gzip","base64","xxd")
  by Processes.dest Processes.user Processes.parent_process_name Processes.process_name
     Processes.process Processes.process_id Processes.parent_process_id
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    match(process_name, "(?i)^(bash|sh|dash)$") AND match(process, "(?i)wget|curl|nc |ncat"), 97,
    match(process_name, "(?i)^(bash|sh|dash)$") AND match(process, "(?i)whoami|id |/etc/passwd|/etc/shadow"), 95,
    match(process_name, "(?i)^(nc|ncat|netcat|socat)$"), 95,
    match(process_name, "(?i)^(bash|sh|dash)$") AND match(process, "(?i)-i |/dev/tcp|/dev/udp"), 97,
    match(process_name, "(?i)^python"), 90,
    match(process_name, "(?i)^(bash|sh|dash)$"), 85,
    1=1, 75)
| where risk_score >= 85
| table firstTime lastTime dest user parent_process_name process_name process process_id risk_score
```

**Query 5 — PHP Webshell File Created in WordPress Directories**

Detects PHP file creation in WordPress plugin or upload directories — the artifact of malicious plugin installation via the wp2shell exploit chain.

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Filesystem
  where Filesystem.file_name="*.php"
    AND (Filesystem.file_path="*/wp-content/plugins/*"
         OR Filesystem.file_path="*/wp-content/uploads/*"
         OR Filesystem.file_path="*/wp-content/mu-plugins/*"
         OR Filesystem.file_path="*/wp-content/themes/*")
    AND Filesystem.action IN ("created","modified")
    AND NOT Filesystem.process_name IN ("php-fpm","php","wp","wpcli","composer")
  by Filesystem.dest Filesystem.user Filesystem.process_name Filesystem.file_path
     Filesystem.file_name Filesystem.action
| `drop_dm_object_name(Filesystem)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    match(file_path, "(?i)/wp-content/uploads/"), 90,
    match(file_path, "(?i)/wp-content/mu-plugins/"), 92,
    match(file_path, "(?i)/wp-content/plugins/") AND NOT match(process_name, "(?i)composer|installer"), 85,
    1=1, 80)
| where risk_score >= 85
| table firstTime lastTime dest user process_name file_path file_name action risk_score
```

## Risk Score Logic

| Condition | Score | Rationale |
|-----------|-------|-----------|
| POST to /wp-json/batch/v1 returning 200 with non-trivial body | 90 | Successful batch endpoint invocation; potential active exploitation |
| SQL injection patterns in WordPress REST API URL | 80–95 | CVE-2026-60137 SQLi probe fingerprint; UNION SELECT is near-definitive |
| Plugin ZIP upload via wp-admin from automated User-Agent | 85 | Post-exploitation plugin webshell staging |
| PHP-FPM spawning bash with download cradle | 97 | Active webshell command execution; near-certain compromise |
| PHP-FPM spawning bash with whoami/id | 95 | Active webshell recon; near-certain compromise |
| PHP file created in /wp-content/uploads/ by unexpected process | 90 | Webshell upload outside plugin flow; high-confidence malicious |
| PHP file created in /wp-content/mu-plugins/ | 92 | Must-use plugin backdoor placement; very rare in legitimate operation |

## Associated Threat Actors

| Actor | Relationship |
|-------|-------------|
| Unknown opportunistic actors | Public PoC available as of July 18, 2026; mass scanning and opportunistic exploitation expected within hours of PoC publication |
| WP-SHELLSTORM (CVE-2026-3844 campaign operator) | WordPress webshell access brokerage group with automated exploitation tooling; the wp2shell PoC fits their mass-exploitation pattern |
| Ransomware affiliates (broad) | WordPress compromise frequently leads to ransomware deployment or data theft; RCE enables direct server access without social engineering |
| Nation-state APT actors (broad) | WordPress sites used as watering holes, command-and-control relay nodes, or credential harvest landing pages |

## References

- [BleepingComputer — WordPress Core wp2shell RCE flaws get public exploits, patch now](https://www.bleepingcomputer.com/news/security/wordpress-core-wp2shell-rce-flaws-get-public-exploits-patch-now/)
- [The Hacker News — New wp2shell WordPress Core Flaw Lets Unauthenticated Attackers Run Code](https://thehackernews.com/2026/07/new-wp2shell-wordpress-core-flaw-lets.html)
- [Rapid7 ETR — CVE-2026-63030: wp2shell Critical RCE in WordPress Core](https://www.rapid7.com/blog/post/etr-cve-2026-63030-wp2shell-a-critical-remote-code-execution-vulnerability-in-wordpress-core/)
- [Hadrian — wp2shell: Pre-Auth RCE in WordPress Core's REST API](https://hadrian.io/blog/wp2shell-a-pre-authentication-rce-in-wordpress-cores-rest-batch-api)
- [Aikido Security — Unauthenticated RCE in WordPress Core (wp2shell)](https://www.aikido.dev/blog/unauthenticated-rce-in-wordpress-wp2shell)
- [Beazley Security Labs — BSL-A1193 wp2shell Critical WordPress RCE Chain](https://labs.beazley.security/advisories/BSL-A1193)
- [MITRE ATT&CK — T1190 Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/)
- [MITRE ATT&CK — T1505.003 Web Shell](https://attack.mitre.org/techniques/T1505/003/)
- [NVD — CVE-2026-63030](https://nvd.nist.gov/vuln/detail/CVE-2026-63030)
- [NVD — CVE-2026-60137](https://nvd.nist.gov/vuln/detail/CVE-2026-60137)
