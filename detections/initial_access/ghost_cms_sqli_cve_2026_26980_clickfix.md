# Ghost CMS SQL Injection Exploitation (CVE-2026-26980) Leading to ClickFix Delivery

## Description

Detects exploitation of CVE-2026-26980, an unauthenticated blind SQL injection in the Ghost CMS Content API affecting versions 3.24.0 through 6.19.0. The vulnerability exists in the Content API filter parameter and allows attackers to read arbitrary database content — including the admin API key — without authentication. Once the admin key is obtained, attackers use the Ghost Admin API to bulk-modify published articles, injecting malicious JavaScript that turns every article page into a ClickFix/FakeCaptcha delivery mechanism. Over 700 Ghost-powered websites were compromised in the May 2026 campaign, including university portals, fintech, media, and AI/SaaS companies.

CISA has not yet added CVE-2026-26980 to the KEV catalog at time of writing. Ghost 6.19.1 patches the vulnerability.

False positives on Search 1 may include penetration test traffic and vulnerability scanners targeting self-hosted Ghost instances. False positives on Search 2 may include legitimate Ghost admin integrations and publishing automation that uses non-browser user agents.

## MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| Tactic | Initial Access |
| Tactic ID | TA0001 |
| Technique | Exploit Public-Facing Application |
| Technique ID | T1190 |
| Secondary Tactic | Initial Access |
| Secondary Technique | Drive-by Compromise |
| Secondary Technique ID | T1189 |

## Lockheed Martin Kill Chain

| Phase |
|-------|
| Exploitation |
| Delivery |

## Splunk Detection Query

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Web.Web
where Web.url LIKE "*/ghost/api/content/*"
  AND (Web.uri_query LIKE "%filter%--%"
    OR Web.uri_query LIKE "%filter%;%"
    OR Web.uri_query LIKE "%filter%UNION%"
    OR Web.uri_query LIKE "%filter%SELECT%"
    OR Web.uri_query LIKE "%filter%SLEEP(%"
    OR Web.uri_query LIKE "%filter%char(%"
    OR Web.uri_query LIKE "%filter%information_schema%"
    OR Web.uri_query LIKE "%filter%0x%"
    OR Web.uri_query LIKE "%filter%CONVERT(%"
    OR Web.uri_query LIKE "%filter%WAITFOR%")
by Web.src Web.dest Web.url Web.uri_query Web.status Web.http_method Web.http_user_agent
| `drop_dm_object_name(Web)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    match(uri_query,"(?i)(UNION\s+SELECT|SLEEP\(\d+\)|WAITFOR\s+DELAY|information_schema)"), 95,
    match(uri_query,"(?i)(CONVERT\(|char\(|0x[0-9a-fA-F]{4,})"), 85,
    match(uri_query,"(--|;%29|%27)"), 75,
    1=1, 65)
| where risk_score >= 65
| table firstTime lastTime src dest url uri_query status http_method http_user_agent risk_score
```

**Supplemental: Suspicious automated bulk article modification via Ghost Admin API (post-exploitation)**

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Web.Web
where Web.url LIKE "*/ghost/api/admin/posts*"
  AND Web.http_method IN ("PUT","POST")
  AND Web.status=200
by Web.src Web.dest Web.url Web.http_method Web.status Web.http_user_agent
| `drop_dm_object_name(Web)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    match(http_user_agent,"(?i)python-requests|python|go-http|libcurl|curl|wget|httpx|java|ruby"), 85,
    match(http_user_agent,"(?i)axios|node-fetch|got|node"), 75,
    1=1, 60)
| where risk_score >= 60
| table firstTime lastTime src dest url http_method status http_user_agent risk_score
```

**Supplemental: DNS resolution of known Ghost CMS ClickFix campaign C2 domains**

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Network_Resolution.DNS
where DNS.query IN ("jalwat.com","taketwolabs.com","com-apps.cc","cloud-verification.com")
by DNS.src DNS.query DNS.answer DNS.record_type
| `drop_dm_object_name(DNS)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=95
| where risk_score >= 95
| table firstTime lastTime src query answer record_type risk_score
```

## Risk Score Logic

| Condition | Score | Rationale |
|-----------|-------|-----------|
| UNION SELECT, SLEEP(), WAITFOR DELAY, or information_schema in Content API filter | 95 | Definitive SQL injection against Ghost CMS Content API — these patterns extract database schema or trigger time-based blind SQLi confirmation |
| CONVERT(), char(), or hex-encoded (0x) payload in filter | 85 | Database encoding and type-conversion SQLi patterns used for data extraction without triggering keyword filters |
| SQL comment sequences (`--`) or bracket encoding in filter | 75 | SQLi comment injection or URL-encoded parameter termination |
| Other SQLi keywords in Ghost Content API filter | 65 | Possible automated scanning against Ghost CMS instances |
| Admin API PUT/POST from scripting user agent | 85 | Automated bulk article modification; legitimate Ghost admin integrations typically use Ghost's own SDKs |
| Known ClickFix domain in DNS query | 95 | Direct hit on campaign infrastructure; no legitimate use of these domains |

## Associated Threat Actors

| Actor | References |
|-------|-----------|
| Unknown (unattributed, financially motivated) | [XLab / Qianxin — CVE-2026-26980 Campaign Analysis](https://blog.xlab.qianxin.com/ghost-cms-mass-compromised-via-cve-2026-26980-now-fueling-clickfix-attacks/), [BleepingComputer](https://www.bleepingcomputer.com/news/security/ghost-cms-sql-injection-flaw-exploited-in-large-scale-clickfix-campaign/) |

## References

- [XLab — Ghost CMS Mass Compromised via CVE-2026-26980, Now Fueling ClickFix Attacks](https://blog.xlab.qianxin.com/ghost-cms-mass-compromised-via-cve-2026-26980-now-fueling-clickfix-attacks/)
- [BleepingComputer — Ghost CMS SQL injection flaw exploited in large-scale ClickFix campaign](https://www.bleepingcomputer.com/news/security/ghost-cms-sql-injection-flaw-exploited-in-large-scale-clickfix-campaign/)
- [NVD — CVE-2026-26980](https://nvd.nist.gov/vuln/detail/CVE-2026-26980)
- [MITRE ATT&CK — T1190 Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/)
- [MITRE ATT&CK — T1189 Drive-by Compromise](https://attack.mitre.org/techniques/T1189/)
- [MITRE ATT&CK — T1204.002 User Execution: Malicious File](https://attack.mitre.org/techniques/T1204/002/)
