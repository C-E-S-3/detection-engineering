# Langflow CVE-2026-9198 Unauthenticated RCE via auto_login + validate/code Chain

## Description

Detects exploitation of CVE-2026-9198 (CVSS 9.8) in IBM Langflow versions 1.0.0–1.10.0. The vulnerability chains two unauthenticated API calls: `POST /api/v1/auto_login` issues a SUPERUSER token to any caller regardless of authentication state; that token is then used with `POST /api/v1/validate/code` to execute arbitrary Python via `exec()`. No valid credentials are required at any step. Added to CISA KEV August 4, 2026. Patched in Langflow 1.10.1.

This is the sixth Langflow CVE exploited in the wild in 2026. False positives are unlikely — `auto_login` is an internal endpoint not used by legitimate clients in normal flows, and `validate/code` is a developer-mode endpoint not expected in production traffic from external IPs. Legitimate Langflow automation that uses these endpoints from known internal IPs may trigger the correlated rule.

## MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| Tactic | Initial Access |
| Tactic ID | TA0001 |
| Technique | Exploit Public-Facing Application |
| Technique ID | T1190 |

Secondary tactic: Execution (TA0002) — T1059.006 (Python) via `exec()` in validate/code

## Lockheed Martin Kill Chain

| Phase |
|-------|
| Exploitation |

## Splunk Detection Query

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Web.Web
  where (Web.uri_path="/api/v1/auto_login" OR Web.uri_path="/api/v1/validate/code")
    AND Web.http_method="POST"
  by Web.src Web.dest Web.uri_path Web.status Web.http_method
| `drop_dm_object_name(Web)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| stats count values(uri_path) as endpoints_hit dc(uri_path) as distinct_endpoints
    min(firstTime) as firstTime max(lastTime) as lastTime
    by src dest
| eval risk_score=case(
    match(endpoints_hit, "auto_login") AND match(endpoints_hit, "validate/code"), 95,
    match(endpoints_hit, "validate/code"), 80,
    match(endpoints_hit, "auto_login"), 55,
    1=1, 40)
| where risk_score >= 55
| table firstTime lastTime src dest endpoints_hit distinct_endpoints count risk_score
```

## Risk Score Logic

| Condition | Score | Rationale |
|-----------|-------|-----------|
| Both `/api/v1/auto_login` AND `/api/v1/validate/code` hit from same source IP | 95 | Completes the full exploit chain — SUPERUSER token issuance followed by arbitrary Python execution; near-certain exploitation attempt |
| Only `/api/v1/validate/code` POST observed | 80 | Code execution endpoint accessed — attacker may have obtained token via other means |
| Only `/api/v1/auto_login` POST observed | 55 | Reconnaissance of the token-issuance endpoint; may be probing before chaining validate/code |

## Associated Threat Actors

| Actor | References |
|-------|-----------|
| Unknown opportunistic actors (CVE-2026-9198, August 2026) | [CISA KEV — CVE-2026-9198](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) |
| MuddyWater (prior Langflow CVE-2025-34291 exploitation) | [MITRE ATT&CK G0069](https://attack.mitre.org/groups/G0069/) |
| JADE PUFFER (prior Langflow CVE-2025-3248 agentic ransomware) | [Sysdig JADE PUFFER Report](https://sysdig.com/blog/jade-puffer-agentic-ransomware-langflow/) |

## References

- [CISA KEV — CVE-2026-9198](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
- [NVD — CVE-2026-9198](https://nvd.nist.gov/vuln/detail/CVE-2026-9198)
- [Langflow 1.10.1 Release](https://github.com/langflow-ai/langflow/releases)
- [MITRE ATT&CK — T1190 Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/)
- [MITRE ATT&CK — T1059.006 Python](https://attack.mitre.org/techniques/T1059/006/)
