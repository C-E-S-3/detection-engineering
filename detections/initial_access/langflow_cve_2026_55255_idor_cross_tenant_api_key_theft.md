# Langflow Cross-Tenant IDOR API Key Theft (CVE-2026-55255)

## Description

Detects exploitation of CVE-2026-55255, a cross-tenant Insecure Direct Object Reference (IDOR) in the Langflow `/api/v1/responses` endpoint (CVSS 9.9). An authenticated attacker enumerates accessible flow UUIDs via GET requests to `/api/v1/flows/`, then POSTs to `/api/v1/responses` supplying flow IDs belonging to other tenants with a crafted input (e.g., `"leak api keys"`). Langflow executes the victim's flow with the attacker's input, returning embedded LLM API keys (OpenAI, Anthropic, Mistral) and AWS credentials in the response.

Active exploitation observed June 22–25, 2026 from `45.207.216.55`. CVE-2026-55255 was added to CISA KEV on July 7, 2026. This vulnerability is frequently chained with CVE-2026-33017 (Langflow unauthenticated RCE). Fixed in Langflow 1.9.2.

**False positives:** Legitimate Langflow administrators or developers running integration tests may generate bulk GET requests to `/api/v1/flows/` and multiple POST requests to `/api/v1/responses`. Tune the `flow_ids_enumerated` threshold and whitelist known admin source IPs.

## MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| Tactic | Initial Access |
| Tactic ID | TA0001 |
| Technique | Exploit Public-Facing Application |
| Technique ID | T1190 |

**Secondary tactic:** Credential Access (TA0006) — T1528: Steal Application Access Token (LLM API keys and AWS credentials exfiltrated via cross-tenant flow execution)

## Lockheed Martin Kill Chain

| Phase |
|-------|
| Exploitation |

## Splunk Detection Query

```spl
| tstats `security_content_summariesonly` dc(Web.url) as flow_ids_enumerated count as request_count min(_time) as firstTime max(_time) as lastTime
from datamodel=Web.Web
where Web.url="*/api/v1/flows/*"
  AND Web.http_method="GET"
by Web.dest Web.src Web.user
| `drop_dm_object_name(Web)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| where flow_ids_enumerated > 5
| join type=inner src dest [
    | tstats `security_content_summariesonly` count as exploit_attempts
    from datamodel=Web.Web
    where Web.url="*/api/v1/responses*"
      AND Web.http_method="POST"
    by Web.dest Web.src
    | `drop_dm_object_name(Web)`
]
| eval risk_score=case(
    flow_ids_enumerated > 20 AND exploit_attempts > 5, 90,
    flow_ids_enumerated > 10 AND exploit_attempts > 0, 75,
    flow_ids_enumerated > 5 AND exploit_attempts > 0, 60,
    1=1, 50)
| where risk_score >= 50
| table firstTime lastTime dest src user flow_ids_enumerated exploit_attempts risk_score
```

## Risk Score Logic

| Condition | Score | Rationale |
|-----------|-------|-----------|
| `flow_ids_enumerated > 20` AND `exploit_attempts > 5` | 90 | Large-scale cross-tenant enumeration combined with high-volume response exploitation; near-certain malicious IDOR campaign |
| `flow_ids_enumerated > 10` AND `exploit_attempts > 0` | 75 | Moderate enumeration with at least one exploitation attempt; high-confidence malicious activity |
| `flow_ids_enumerated > 5` AND `exploit_attempts > 0` | 60 | Suspicious enumeration correlated with response endpoint access; requires analyst review to confirm cross-tenant targeting |

## Associated Threat Actors

| Actor | References |
|-------|-----------|
| Unknown opportunistic actors (CVE-2026-55255 campaign, June 2026) | [Sysdig TRT — CVE-2026-55255](https://www.sysdig.com/blog/understanding-langflow-cve-2026-55255-and-why-higher-cvss-vulnerabilities-arent-always-the-most-exploited) |

## References

- [Sysdig TRT — CVE-2026-55255 Analysis](https://www.sysdig.com/blog/understanding-langflow-cve-2026-55255-and-why-higher-cvss-vulnerabilities-arent-always-the-most-exploited)
- [CISA KEV — CVE-2026-55255 (added 2026-07-07)](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
- [MITRE ATT&CK T1190 — Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/)
- [MITRE ATT&CK T1528 — Steal Application Access Token](https://attack.mitre.org/techniques/T1528/)
- [NVD CVE-2026-55255](https://nvd.nist.gov/vuln/detail/CVE-2026-55255)
