# JFrog Artifactory Unauthenticated Admin Token Minting (CVE-2026-82329)

## Description

Detects exploitation of CVE-2026-82329, a CVSS 9.8 critical authentication bypass in JFrog Artifactory. In the default configuration, unauthenticated attackers can send HTTP requests to the Artifactory REST API token endpoint and receive back an administrator-level access token without providing any credentials. Active exploitation was confirmed September 1, 2026 via WatchTowr honeypot telemetry.

Post-exploitation activity typically includes immediate user, group, and federated topology enumeration, followed by account creation, permission escalation, and repository/artifact access. Successful compromise of Artifactory gives attackers full control of hosted packages and build artifacts, making this a high-value supply chain attack vector.

**False positive sources:**
- Legitimate admin token generation by automation accounts should always include an authenticated session; review source IPs and associated user context
- Bulk token creation during Artifactory upgrades or migration tasks

## MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| Tactic | Initial Access |
| Tactic ID | TA0001 |
| Technique | Exploit Public-Facing Application |
| Technique ID | T1190 |
| Secondary Tactic | Credential Access |
| Secondary Technique | Steal Application Access Token (T1528) |

## Lockheed Martin Kill Chain

| Phase |
|-------|
| Exploitation |

## Splunk Detection Query

### Query 1: Unauthenticated Artifactory REST API Token Creation

Detects unauthenticated POST requests to the Artifactory access token API endpoint. In a patched or hardened environment these should always have an authenticated session; unauthenticated token-creation requests are a direct exploitation indicator.

```spl
index=* sourcetype=artifactory:access OR sourcetype=jfrog:artifactory
(action="create_token" OR action="GenerateToken" OR uri="*/artifactory/api/security/token*" OR uri="*/access/api/v1/tokens*")
NOT (username!="" AND username!="anonymous" AND username!="unauthenticated")
| eval is_unauth=if(isnull(username) OR username="anonymous" OR username="unauthenticated", "true", "false")
| where is_unauth="true"
| stats count min(_time) as firstTime max(_time) as lastTime values(src_ip) as source_ips values(uri) as uri_list by host
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    count >= 10, 95,
    count >= 3, 85,
    count >= 1, 75)
| where risk_score >= 75
| table firstTime lastTime host source_ips uri_list count risk_score
```

### Query 2: Artifactory Admin API Activity Following Token Creation (Behavioral Chain)

Detects a rapid sequence of admin-level API calls (user/group/permission enumeration) following token creation — consistent with post-exploitation reconnaissance.

```spl
index=* sourcetype=artifactory:access OR sourcetype=jfrog:artifactory
(uri="*/artifactory/api/security/users*" OR uri="*/artifactory/api/security/groups*" OR uri="*/access/api/v1/users*" OR uri="*/access/api/v1/groups*" OR uri="*/artifactory/api/system/configuration*")
| bucket _time span=5m
| stats count dc(uri) as distinct_endpoints values(src_ip) as source_ips values(uri) as uri_list min(_time) as firstTime max(_time) as lastTime by host _time
| where count >= 5 AND distinct_endpoints >= 3
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    distinct_endpoints >= 5, 90,
    distinct_endpoints >= 3, 80)
| where risk_score >= 80
| table firstTime lastTime host source_ips distinct_endpoints uri_list count risk_score
```

### Query 3: Wazuh Rule — Artifactory Unauthenticated Token Request (Web Log)

For environments using Wazuh with Traefik or nginx JSON access logs fronting Artifactory:

```spl
index=wazuh data.rule.id IN ("104200","104201","104202")
| stats count min(_time) as firstTime max(_time) as lastTime values(data.srcip) as source_ips by data.hostname data.rule.description
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=95
| table firstTime lastTime data.hostname source_ips data.rule.description count risk_score
```

## Risk Score Logic

| Condition | Score | Rationale |
|-----------|-------|-----------|
| Single unauthenticated token creation attempt | 75 | Direct exploitation indicator; no benign explanation for unauth token minting |
| 3+ unauthenticated token creation attempts | 85 | Active exploitation or automated scanning confirmed |
| 10+ unauthenticated token creation attempts | 95 | Mass exploitation or automated exploit tool; immediate response required |
| Rapid multi-endpoint admin API enumeration (5+ calls, 3+ distinct endpoints in 5 min) | 80–90 | Post-exploitation reconnaissance pattern |

## Associated Threat Actors

| Actor | References |
|-------|-----------|
| Unknown opportunistic actors (multiple IPs, varying geographies) | WatchTowr Attacker Eye honeypot telemetry, September 1, 2026 |
| Potential nation-state supply chain actors | Artifactory is a high-value CI/CD target for artifact poisoning; consistent with TeamPCP/UNC6780 TTPs |
| Potential initial access brokers | Credential and repository access saleable; consistent with IAB reconnaissance patterns |

## References

- [The Hacker News — Attackers Exploit Critical JFrog Artifactory Vulnerability](https://thehackernews.com/2026/09/attackers-exploit-critical-jfrog.html)
- [SecurityWeek — Critical JFrog Artifactory Vulnerability Reportedly Exploited in the Wild](https://www.securityweek.com/critical-jfrog-artifactory-vulnerability-reportedly-exploited-in-the-wild/)
- [Dark Reading — Attackers Pounce on Critical Artifactory Flaw at Disclosure](https://www.darkreading.com/application-security/attackers-pounce-critical-artifactory-flaw-disclosure)
- [dev.to/anoymask — Exploitation of JFrog Artifactory CVE-2026-82329](https://dev.to/anoymask/exploitation-of-jfrog-artifactory-cve-2026-82329-unauthenticated-administrator-token-generation-je1)
- [MITRE ATT&CK T1190 — Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/)
- [MITRE ATT&CK T1528 — Steal Application Access Token](https://attack.mitre.org/techniques/T1528/)
- [JFrog Security Advisory — CVE-2026-82329](https://jfrog.com/security-advisory/)
- [NVD CVE-2026-82329](https://nvd.nist.gov/vuln/detail/CVE-2026-82329)
