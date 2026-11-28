# GeoServer WFS Stored Query XML Injection (CVE-2026-120705 + CVE-2026-129243)

## Description

Detects exploitation of the GeoServer unauthenticated RCE chain: CVE-2026-129243 (service-rule auth bypass via slash-prefixed `service` parameter) chained with CVE-2026-120705 (WFS GetFeatureById stored-query XML injection enabling file read). Both CVEs were added to CISA KEV on 2026-11-27 with a remediation deadline of 2026-11-30 (BOD 26-04). Exploitation was observed on watchTowr honeypots beginning 2026-11-25.

The detection covers three patterns:
1. The service-rule bypass pattern (`service=*/WFS` with slash-prefixed path)
2. WFS stored query creation (`CreateStoredQuery`) or invocation (`GetFeatureById`), which are the payload delivery step
3. Combined detection: source IP submitting a service bypass request AND a stored query operation within a short window

False positive sources: legitimate GeoServer applications that call stored queries via GetFeatureById for internal business logic. Tune by scoping the destination to externally accessible GeoServer instances. `CreateStoredQuery` is rarely used in production workflows and should almost always be investigated.

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
| Tactic | Credential Access |
| Tactic ID | TA0006 |
| Technique | Credentials In Files |
| Technique ID | T1552.001 |

## Lockheed Martin Kill Chain

| Phase |
|-------|
| Delivery |
| Exploitation |

## Splunk Detection Query

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Web.Web
where (Web.url="*/ows*" OR Web.url="*/wfs*" OR Web.url="*/wcs*")
  AND (Web.url="*service=*%2F*" OR Web.url="*service=*/*"
       OR Web.url="*CreateStoredQuery*" OR Web.url="*GetFeatureById*"
       OR Web.url="*DropStoredQuery*" OR Web.url="*DescribeStoredQueries*")
by Web.src Web.dest Web.url Web.http_method Web.user_agent Web.status Web.bytes
| `drop_dm_object_name(Web)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    match(url, "CreateStoredQuery"), 90,
    match(url, "GetFeatureById"), 85,
    match(url, "service=[^&=]*%2FWFS|service=[^&=]*/WFS"), 80,
    match(url, "service=[^&=]*/"), 70,
    1=1, 60)
| where risk_score >= 60
| table firstTime lastTime src dest url http_method user_agent status risk_score
```

## Risk Score Logic

| Condition | Score | Rationale |
|-----------|-------|-----------|
| `CreateStoredQuery` in URL | 90 | Stored query creation is the payload-planting step in the exploit chain; rarely used in legitimate production workflows |
| `GetFeatureById` in URL | 85 | Payload invocation step that triggers file read in the exploit chain; legitimate use exists but should be scoped |
| `service=*/WFS` or `service=*%2FWFS` | 80 | Specific bypass pattern — slash-prefixed service parameter bypasses security rules; not used by standard clients |
| Any `service=*/` pattern | 70 | Generic slash-prefixed service bypass; warrants investigation |

## Associated Threat Actors

| Actor | References |
|-------|-----------|
| Unknown opportunistic actors (November 2026) | [CISA KEV 2026-11-27](https://www.cisa.gov/news-events/alerts/2026/11/27/cisa-adds-three-known-exploited-vulnerabilities-catalog), [watchTowr honeypot telemetry 2026-11-25](https://zerohour.day/item/43b51045fd66057586e80b07ca9b72d99d9be419) |

## References

- [CISA KEV Alert 2026-11-27](https://www.cisa.gov/news-events/alerts/2026/11/27/cisa-adds-three-known-exploited-vulnerabilities-catalog)
- [GeoServer CVE-2026-120705 — WFS stored query XML injection](https://github.com/geoserver/geoserver/security/advisories)
- [GeoServer CVE-2026-129243 — service-rule auth bypass](https://github.com/geoserver/geoserver/security/advisories)
- [MITRE ATT&CK T1190 — Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/)
- [MITRE ATT&CK T1552.001 — Credentials In Files](https://attack.mitre.org/techniques/T1552/001/)
- [Threat Intel Report](../../threat-intel/2026-11-28_cisa-kev-geoserver-cve-2026-120705-cve-2026-129243-unauthenticated-rce-chain.md)
