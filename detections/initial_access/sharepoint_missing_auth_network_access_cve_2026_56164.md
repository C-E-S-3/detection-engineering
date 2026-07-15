# SharePoint Server Missing Authentication Exploitation (CVE-2026-56164)

## Description

Detects exploitation of CVE-2026-56164 (CVSS 5.3, CWE: Missing Authentication for Critical Function) in Microsoft SharePoint Server 2016, 2019, and Subscription Edition. The vulnerability allows an unauthenticated network-adjacent attacker to access a critical SharePoint function with no credentials and no user interaction required. Added to CISA KEV on July 14, 2026 with confirmed in-the-wild exploitation.

This detection focuses on anomalous POST requests to SharePoint endpoints that lack authentication context (no authenticated session cookie or NTLM/Kerberos token). Legitimate SharePoint usage from unauthenticated clients is rare in most enterprise deployments; this pattern is a strong indicator of exploitation attempts.

False positive sources: SharePoint health check probes configured without authentication, legitimate anonymous SharePoint publishing sites with POST-capable pages, misconfigured crawlers.

## MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| Tactic | Initial Access |
| Tactic ID | TA0001 |
| Technique | Exploit Public-Facing Application |
| Technique ID | T1190 |

## Lockheed Martin Kill Chain

| Phase |
|-------|
| Delivery |
| Exploitation |

## Splunk Detection Query

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Web.Web
where (Web.dest_category="sharepoint_server" OR Web.app="SharePoint")
  AND Web.http_method="POST"
  AND (Web.user="-" OR Web.user="anonymous" OR Web.user="")
  AND Web.status IN ("200", "201", "204", "302", "500")
by Web.src Web.dest Web.url Web.http_method Web.status Web.user Web.user_agent Web.bytes_in
| `drop_dm_object_name(Web)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    status="200" AND (user="-" OR user="anonymous" OR user=""), 90,
    status IN ("201", "204") AND (user="-" OR user="anonymous" OR user=""), 85,
    status="500" AND (user="-" OR user="anonymous" OR user=""), 70,
    1=1, 55)
| where risk_score >= 55
| table firstTime lastTime src dest url http_method status user user_agent bytes_in risk_score
```

## Risk Score Logic

| Condition | Score | Rationale |
|-----------|-------|-----------|
| Unauthenticated POST returns HTTP 200 (success) | 90 | Successful unauthenticated POST to SharePoint is strong indicator of CVE-2026-56164 exploitation |
| Unauthenticated POST returns HTTP 201/204 (resource created/no content) | 85 | Server accepted and processed unauthenticated write operation |
| Unauthenticated POST returns HTTP 500 (server error) | 70 | Failed exploitation attempt; server processing the request indicates the vulnerable code path was reached |
| Unauthenticated POST, other response | 55 | Baseline detection; analyst should correlate with known scanner IPs and volume |

## Associated Threat Actors

| Actor | References |
|-------|-----------|
| Unknown (actively exploited, CISA KEV July 14, 2026) | [CISA KEV Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) |

## References

- [Tenable — Microsoft July 2026 Patch Tuesday (2026-07-14)](https://www.tenable.com/blog/microsofts-july-2026-patch-tuesday-addresses-569-cves-cve-2026-56155-cve-2026-56164)
- [CISA KEV — CVE-2026-56164](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
- [Microsoft Security Update Guide — July 2026](https://msrc.microsoft.com/update-guide/)
- [MITRE ATT&CK T1190](https://attack.mitre.org/techniques/T1190/)
