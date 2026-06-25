# SimpleHelp OIDC Authentication Bypass (CVE-2026-48558)

## Description

Detects exploitation of CVE-2026-48558, a critical authentication bypass in SimpleHelp remote support software. When OIDC authentication is enabled with a Technician Group associated with the OIDC provider, an unauthenticated attacker can send a forged OIDC callback to create a rogue Technician account without passing MFA. The attacker then uses this account to remote into managed endpoints and execute scripts.

Approximately 14,000 SimpleHelp servers are publicly exposed (Shodan), with ~7.2% using OIDC. Fixed in versions 5.5.16 and 6.0RC2 (released 2026-06-09).

**False positive sources:** Legitimate OIDC logins by authorized technicians will trigger 102507 (server.log OIDC login). Rules anchored on the POST callback endpoint (102500-102501) may be noisy if SimpleHelp uses non-standard OIDC callback paths. The two-stage correlation rule (102505) represents confirmed attack activity.

## MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| Tactic | Initial Access |
| Tactic ID | TA0001 |
| Technique | Exploit Public-Facing Application |
| Technique ID | T1190 |
| Secondary Tactic | Persistence |
| Secondary Tactic ID | TA0003 |
| Secondary Technique | Create Account: Local Account |
| Secondary Technique ID | T1136.001 |
| Tertiary Technique | Valid Accounts |
| Tertiary Technique ID | T1078 |

## Lockheed Martin Kill Chain

| Phase |
|-------|
| Exploitation |
| Installation |

## Wazuh Rules

| Rule ID | Level | Description |
|---------|-------|-------------|
| 102500 | 12 | POST to SimpleHelp OIDC callback — auth bypass attempt |
| 102501 | 15 | OIDC endpoint returned 2xx — rogue account creation succeeded |
| 102502 | 12 | SimpleHelp remote management endpoint accessed |
| 102503 | 9 | SimpleHelp OIDC endpoint probe — reconnaissance |
| 102504 | 14 | 3+ OIDC POST attempts in 120s — automated exploit |
| 102505 | 15 | Two-stage: OIDC bypass then technician session — confirmed |
| 102506 | 13 | New technician registration in server.log |
| 102507 | 12 | OIDC login event in server.log |
| 102508 | 14 | Script execution event in server.log post-OIDC |

## Splunk Detection Query

```spl
index=web sourcetype=traefik_json
  uri_path="/remote/oidc/*"
| eval oidc_post=if(http_method="POST" AND match(uri_path,"^/remote/oidc/(callback|token|login|auth)"),1,0)
| eval oidc_recon=if(match(uri_path,"^/remote/oidc/"),1,0)
| eval session_access=if(match(uri_path,"^/remote/(admin|technician|session|support)"),1,0)
| stats count as total_requests
    sum(oidc_post) as oidc_post_attempts
    sum(oidc_recon) as oidc_recon_hits
    sum(session_access) as session_hits
    values(uri_path) as paths
    values(http_status) as statuses
    min(_time) as firstTime max(_time) as lastTime
    by src_ip dest_host
| eval oidc_success=if(oidc_post_attempts > 0 AND mvfind(statuses,"^2\d{2}") >= 0, 1, 0)
| eval risk_score=case(
    oidc_success=1 AND session_hits > 0, 100,
    oidc_success=1, 90,
    oidc_post_attempts >= 3, 75,
    oidc_post_attempts > 0, 65,
    oidc_recon_hits >= 5, 50,
    1=1, 30)
| where risk_score >= 65
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| table firstTime lastTime src_ip dest_host oidc_post_attempts oidc_success session_hits paths risk_score
```

## Risk Score Logic

| Condition | Score | Rationale |
|-----------|-------|-----------|
| OIDC POST succeeded (2xx) + session access | 100 | Two-stage confirmed: rogue account created and used |
| OIDC POST returned 2xx | 90 | Account creation succeeded |
| 3+ OIDC POST attempts | 75 | Automated exploitation tool |
| Any OIDC POST attempt | 65 | Authentication bypass probe |
| 5+ OIDC recon probes | 50 | Pre-exploitation fingerprinting |

## Associated Threat Actors

| Actor | References |
|-------|-----------|
| Opportunistic attackers targeting remote support tools | [MITRE T1190](https://attack.mitre.org/techniques/T1190/) |
| Ransomware affiliates (initial access via RMM tools) | [MITRE T1136.001](https://attack.mitre.org/techniques/T1136/001/) |

## References

- [BleepingComputer — SimpleHelp CVE-2026-48558](https://www.bleepingcomputer.com/news/security/simplehelp-bug-lets-hackers-create-rogue-remote-support-accounts/)
- [MITRE ATT&CK T1190](https://attack.mitre.org/techniques/T1190/)
- [MITRE ATT&CK T1136.001](https://attack.mitre.org/techniques/T1136/001/)
- [SimpleHelp Security Advisory](https://simple-help.com/security-advisories)
- [Shodan: ~14,000 exposed SimpleHelp servers](https://www.shodan.io/)
