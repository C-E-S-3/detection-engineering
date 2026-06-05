# Mirasvit Full Page Cache Warmer PHP Object Injection RCE (CVE-2026-45247)

## Description

Detects active exploitation of CVE-2026-45247 (CVSS 9.8), a critical unauthenticated remote code execution vulnerability in Mirasvit Full Page Cache Warmer for Magento 2 (versions < 1.11.12). The extension passes the `CacheWarmer` HTTP cookie value directly to PHP's native `unserialize()` function without class restrictions or authentication, enabling PHP Object Injection. Attackers chain this with a PHP gadget chain (e.g., Laminas/Zend chains available in Magento's Composer dependencies) to achieve unauthenticated RCE as the PHP-FPM or web server process. Exploitation requires no credentials, no admin session, and no special configuration — a single crafted storefront request is sufficient.

**Detection logic:** PHP serialized objects base64-encode to values beginning with `Tz`, `Qz`, or `YT`. Any HTTP request carrying a `CacheWarmer` cookie whose value begins with these prefixes is a strong indicator of an active exploitation attempt. CISA added CVE-2026-45247 to the KEV catalog on June 3, 2026, confirming active in-the-wild exploitation.

**False positives:** Legitimate CacheWarmer cookie values are short numeric or alphanumeric strings set by the extension for cache-warming logic. Base64-encoded serialized PHP objects in the CacheWarmer cookie are not part of normal cache-warming behavior; false positive rate is expected to be very low.

## MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| Tactic | Initial Access |
| Tactic ID | TA0001 |
| Technique | Exploit Public-Facing Application |
| Technique ID | T1190 |

Secondary: Execution (T1203 — Exploitation for Client Execution) via PHP gadget chain deserialization; Persistence (T1505.003 — Web Shell) post-exploitation.

## Lockheed Martin Kill Chain

| Phase |
|-------|
| Exploitation |

## Splunk Detection Query

```spl
`web`
| rex field=cookie "CacheWarmer=(?P<cw_cookie_value>[^;,\s]+)"
| where isnotnull(cw_cookie_value)
    AND match(cw_cookie_value, "^(Tz|Qz|YT)")
| stats count min(_time) as firstTime max(_time) as lastTime
    values(uri_path) as uri_path
    values(cw_cookie_value) as cw_cookie_value
    by src dest
| eval risk_score=90
| where risk_score >= 90
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| table firstTime lastTime src dest uri_path cw_cookie_value count risk_score
```

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Endpoint.Processes
where Processes.parent_process_name IN ("php-fpm", "php", "apache2", "httpd", "nginx", "php8.1-fpm", "php8.2-fpm")
  AND Processes.process_name IN ("sh", "bash", "curl", "wget", "python", "python3",
    "nc", "ncat", "id", "whoami", "uname", "cat", "cp", "mv")
by Processes.dest Processes.user Processes.parent_process_name
   Processes.process_name Processes.process Processes.process_id
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    process_name IN ("id", "whoami", "uname"), 95,
    process_name IN ("curl", "wget", "nc", "ncat"), 88,
    process_name IN ("sh", "bash", "python", "python3"), 80,
    1=1, 70)
| where risk_score >= 70
| table firstTime lastTime dest user parent_process_name process_name process risk_score
```

## Risk Score Logic

| Condition | Score | Rationale |
|-----------|-------|-----------|
| `CacheWarmer` cookie value starts with `Tz`, `Qz`, or `YT` | 90 | PHP serialized objects base64-encode to exactly these prefixes; no legitimate cookie value matches this pattern; near-certain exploitation attempt per Sansec/Imperva research |
| PHP web process (`php-fpm`, `apache2`, `httpd`) spawning `id`/`whoami`/`uname` | 95 | Command execution confirmation post-exploit; legitimate PHP processes do not spawn identity commands |
| PHP web process spawning `curl`/`wget`/`nc` | 88 | Download cradle or reverse shell setup post-exploitation |
| PHP web process spawning `sh`/`bash` | 80 | Shell access post-exploitation; broader false positive surface but still highly suspicious |

## Associated Threat Actors

| Actor | References |
|-------|-----------|
| MageCart Groups (multiple) | [MITRE ATT&CK — Magecart (G0090)](https://attack.mitre.org/groups/G0090/), [Sansec — Magecart Research](https://sansec.io/research/magecart) |
| Unknown / Opportunistic Mass-Exploitation Actors | [CISA KEV — CVE-2026-45247 (June 3, 2026)](https://www.cisa.gov/news-events/alerts/2026/06/03/cisa-adds-one-known-exploited-vulnerability-catalog) |

## References

- [CISA KEV — CVE-2026-45247 (June 3, 2026)](https://www.cisa.gov/news-events/alerts/2026/06/03/cisa-adds-one-known-exploited-vulnerability-catalog)
- [Sansec — Mirasvit Cache Warmer Object Injection (May 26, 2026)](https://sansec.io/research/mirasvit-cache-warmer-object-injection)
- [Imperva — Active Exploitation of CVE-2026-45247](https://www.imperva.com/blog/imperva-customers-protected-against-cve-2026-45247-in-mirasvit-full-page-cache-warmer-for-magento/)
- [THN — CISA Adds Exploited Magento RCE Flaw CVE-2026-45247](https://thehackernews.com/2026/06/cisa-adds-exploited-magento-rce-flaw.html)
- [MITRE ATT&CK — T1190: Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/)
- [PHPGGC — PHP Generic Gadget Chains](https://github.com/ambionics/phpggc)
