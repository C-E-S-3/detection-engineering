# JFrog Artifactory Token Scope Bypass Chain (CVE-2026-42016 / CVE-2026-42018)

## Description

Detects exploitation of the chained JFrog Artifactory vulnerabilities CVE-2026-42018 (CVSS 7.5) and CVE-2026-42016 (CVSS 8.1), added to CISA KEV September 12, 2026.

CVE-2026-42018 causes Artifactory to return its internal anonymous-user token to unauthenticated callers even when anonymous access is explicitly disabled. CVE-2026-42016 then allows that token (or any token) to be used beyond its intended scope because authorization logic validates the token signature and issuer but not the scope. Chained together — and in combination with the previously-tracked CVE-2026-82329 — an unauthenticated attacker achieves full administrative control over the Artifactory instance.

Observed post-exploitation activity includes persistent admin account creation, malicious Groovy plugin deployment for arbitrary JVM code execution, and Rust-based backdoor installation. Artifactory is a high-value supply chain target; successful compromise enables artifact poisoning affecting all downstream software consumers.

**False positive sources:**
- Legitimate anonymous token issuance when anonymous access is intentionally enabled (check Artifactory configuration)
- Automation accounts performing rapid bulk admin operations during migrations

## MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| Tactic | Initial Access |
| Tactic ID | TA0001 |
| Technique | Exploit Public-Facing Application |
| Technique ID | T1190 |
| Secondary Tactic | Credential Access |
| Secondary Technique | Steal Application Access Token (T1528) |
| Secondary Tactic | Persistence |
| Secondary Technique | Server Software Component (T1505) |

## Lockheed Martin Kill Chain

| Phase |
|-------|
| Exploitation |
| Installation |

## Splunk Detection Query

### Query 1: Anonymous Token Issued When Anonymous Access Is Disabled

Detects Artifactory returning an anonymous token to a caller when no authenticated session is present — the direct signal of CVE-2026-42018 exploitation.

```spl
index=* sourcetype IN ("artifactory:access","jfrog:artifactory","jfrog:access")
(action="create_token" OR action="GenerateToken"
 OR uri="*/access/api/v1/tokens*" OR uri="*/artifactory/api/security/token*")
| eval is_anon_token=if(match(coalesce(token_scope,token_type,""),"(?i)anonymous|member-of-groups:")
    AND (isnull(username) OR username IN ("anonymous","","unauthenticated")), "true", "false")
| where is_anon_token="true"
| stats count min(_time) as firstTime max(_time) as lastTime values(src_ip) as source_ips values(uri) as uri_list by host
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(count>=5, 95, count>=1, 85)
| where risk_score >= 85
| table firstTime lastTime host source_ips uri_list count risk_score
```

### Query 2: Token Scope Escalation — Privilege Mismatch (CVE-2026-42016)

Detects an API call that uses a token to perform an action outside the token's declared scope — the CVE-2026-42016 exploitation signal.

```spl
index=* sourcetype IN ("artifactory:access","jfrog:artifactory","jfrog:access")
(action IN ("create_user","update_user","create_group","update_permission","assign_role")
 OR uri="*/access/api/v1/users*" OR uri="*/access/api/v1/groups*"
 OR uri="*/artifactory/api/security/permissions*")
| eval caller_scope=coalesce(token_scope,"unknown")
| where match(caller_scope,"(?i)anonymous|applied-permissions/anonymous|member-of-groups:")
| stats count min(_time) as firstTime max(_time) as lastTime values(src_ip) as source_ips
        values(uri) as uri_list values(action) as actions by host username
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=95
| table firstTime lastTime host username source_ips uri_list actions count risk_score
```

### Query 3: Post-Exploitation Enumeration Sequence

Detects rapid multi-endpoint admin API calls within 5 minutes of token issuance — consistent with post-exploitation reconnaissance using a freshly minted admin token.

```spl
index=* sourcetype IN ("artifactory:access","jfrog:artifactory","jfrog:access")
(uri="*/artifactory/api/security/users*"
 OR uri="*/artifactory/api/security/groups*"
 OR uri="*/access/api/v1/users*"
 OR uri="*/access/api/v1/groups*"
 OR uri="*/artifactory/api/system/configuration*"
 OR uri="*/artifactory/api/plugins*"
 OR uri="*/artifactory/api/repositories*")
| bucket _time span=5m
| stats count dc(uri) as distinct_endpoints values(src_ip) as source_ips
        values(uri) as uri_list min(_time) as firstTime max(_time) as lastTime
        by host _time
| where count >= 5 AND distinct_endpoints >= 3
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(distinct_endpoints >= 6, 90, distinct_endpoints >= 3, 80)
| where risk_score >= 80
| table firstTime lastTime host source_ips distinct_endpoints uri_list count risk_score
```

### Query 4: Groovy Plugin Upload (Persistence Indicator)

Detects a POST to the Artifactory plugins API — the mechanism attackers use to deploy persistent malicious Groovy code execution.

```spl
index=* sourcetype IN ("artifactory:access","jfrog:artifactory","jfrog:access")
(uri="*/artifactory/api/plugins*" AND method="POST")
| stats count min(_time) as firstTime max(_time) as lastTime values(src_ip) as source_ips
        values(uri) as uri_list values(username) as usernames by host
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=95
| table firstTime lastTime host usernames source_ips uri_list count risk_score
```

## Risk Score Logic

| Condition | Score | Rationale |
|-----------|-------|-----------|
| Anonymous token issued with no authenticated session | 85 | Direct CVE-2026-42018 exploitation signal |
| Anonymous-scoped token used for admin API action | 95 | Direct CVE-2026-42016 scope bypass exploitation signal |
| 5+ admin API calls across 3+ distinct endpoints within 5 min | 80–90 | Post-exploitation reconnaissance pattern |
| Groovy plugin POST | 95 | Persistence installation; almost no legitimate use case for API-driven plugin upload |

## Associated Threat Actors

| Actor | References |
|-------|-----------|
| Unknown opportunistic actors | Active exploitation Aug 15–Sep 8 2026; multiple organizations; CISA KEV Sep 12 2026 |
| Potential supply chain threat actors | Artifactory artifact poisoning is consistent with TeamPCP/UNC6780-style CI/CD supply chain TTPs |

## References

- [The Hacker News — CISA Adds 5 Actively Exploited Artifactory, ScreenConnect, and RouterOS Flaws to KEV](https://thehackernews.com/2026/09/cisa-adds-5-actively-exploited.html)
- [CISA Known Exploited Vulnerabilities Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
- [NVD — CVE-2026-42016](https://nvd.nist.gov/vuln/detail/CVE-2026-42016)
- [NVD — CVE-2026-42018](https://nvd.nist.gov/vuln/detail/CVE-2026-42018)
- [Threat Intel Report — CISA KEV Sep 12 2026](../../threat-intel/2026-09-14_cisa-kev-jfrog-artifactory-screenconnect-cve-2026-42016-42018-84869.md)
- [Detection — JFrog Artifactory CVE-2026-82329 Unauthenticated Admin Token Minting](jfrog_artifactory_unauth_admin_token_minting.md)
- [MITRE ATT&CK — T1190 Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/)
- [MITRE ATT&CK — T1528 Steal Application Access Token](https://attack.mitre.org/techniques/T1528/)
- [MITRE ATT&CK — T1505 Server Software Component](https://attack.mitre.org/techniques/T1505/)
