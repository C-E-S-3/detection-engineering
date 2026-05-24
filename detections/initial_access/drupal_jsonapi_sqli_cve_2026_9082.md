# Drupal JSON:API SQL Injection Exploitation (CVE-2026-9082)

## Description

Detects exploitation attempts targeting CVE-2026-9082, a SQL injection vulnerability in Drupal Core's JSON:API module affecting PostgreSQL-backed installations. The flaw exists in the `translateCondition()` method, which uses user-supplied JSON:API filter parameter **array keys** (not values) as PDO placeholder names without sanitization. Attackers send unauthenticated GET or POST requests to `/jsonapi/<entity_type>/<bundle>` with specially crafted filter array keys containing SQL injection payloads (SQL keywords, comment sequences, timing functions). Successful exploitation allows database read/write access enabling account takeover, credential theft, and potentially RCE via database write capabilities.

CISA added CVE-2026-9082 to the Known Exploited Vulnerabilities catalog on May 22, 2026 with a FCEB remediation deadline of May 27, 2026. Over 15,000 exploitation attempts observed against ~6,000 sites globally.

False positives may occur from legitimate JSON:API clients using unusual filter syntax; tune by excluding known safe source IPs and adding `http_user_agent` allowlisting.

## MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| Tactic | Initial Access |
| Tactic ID | TA0001 |
| Technique | Exploit Public-Facing Application |
| Technique ID | T1190 |
| Secondary Tactic | Privilege Escalation |
| Secondary Tactic ID | TA0004 |
| Secondary Technique | Exploitation for Privilege Escalation |
| Secondary Technique ID | T1068 |

## Lockheed Martin Kill Chain

| Phase |
|-------|
| Exploitation |

## Splunk Detection Query

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Web.Web
where Web.url LIKE "*/jsonapi/*"
  AND (Web.uri_query LIKE "%filter%--%"
    OR Web.uri_query LIKE "%filter%);%"
    OR Web.uri_query LIKE "%filter%UNION%"
    OR Web.uri_query LIKE "%filter%SELECT%"
    OR Web.uri_query LIKE "%filter%SLEEP%"
    OR Web.uri_query LIKE "%filter%WAITFOR%"
    OR Web.uri_query LIKE "%filter%0x%"
    OR Web.uri_query LIKE "%filter%pg_sleep%"
    OR Web.uri_query LIKE "%filter%version()%"
    OR Web.uri_query LIKE "%filter%pg_catalog%"
    OR Web.uri_query LIKE "%filter%information_schema%")
by Web.src Web.dest Web.url Web.uri_query Web.status Web.http_method Web.http_user_agent
| `drop_dm_object_name(Web)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    match(uri_query,"(?i)(UNION\s+SELECT|pg_sleep|WAITFOR\s+DELAY)"), 90,
    match(uri_query,"(?i)(information_schema|pg_catalog|version\(\))"), 80,
    match(uri_query,"(--|;%29|%27)"), 75,
    1=1, 65)
| where risk_score >= 65
| table firstTime lastTime src dest url uri_query status http_method http_user_agent risk_score
```

## Risk Score Logic

| Condition | Score | Rationale |
|-----------|-------|-----------|
| UNION SELECT, pg_sleep, or WAITFOR DELAY in filter key | 90 | Definitive SQL injection or time-based blind SQLi pattern |
| information_schema or pg_catalog enumeration | 80 | Database schema enumeration following initial SQLi confirmation |
| SQL comment (`--`) or bracket/quote encoding in filter key | 75 | SQLi comment injection or parameter termination attempt |
| Other SQLi keywords in filter parameter | 65 | Possible automated scanning |

## Associated Threat Actors

| Actor | References |
|-------|-----------|
| Opportunistic mass-exploitation (unattributed) | [CISA KEV May 22, 2026](https://www.cisa.gov/news-events/alerts/2026/05/22/cisa-adds-one-known-exploited-vulnerability-catalog), [Imperva telemetry via Thales](https://thehackernews.com/2026/05/drupal-core-sql-injection-bug-actively.html) |

## References

- [CISA KEV Alert — CVE-2026-9082 Added May 22, 2026](https://www.cisa.gov/news-events/alerts/2026/05/22/cisa-adds-one-known-exploited-vulnerability-catalog)
- [Drupal Security Advisory SA-CORE-2026-004](https://www.drupal.org/sa-core-2026-004)
- [Tenable — CVE-2026-9082 Analysis](https://www.tenable.com/blog/cve-2026-9082-highly-critical-sql-injection-vulnerability-in-drupal-core-sa-core-2026-004)
- [The Hacker News — Drupal Core SQL Injection Bug Actively Exploited](https://thehackernews.com/2026/05/drupal-core-sql-injection-bug-actively.html)
- [MITRE ATT&CK T1190 — Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/)
