# Cisco Catalyst SD-WAN Manager Authenticated Path Traversal (CVE-2026-20262)

## Description

Detects exploitation of CVE-2026-20262, an authenticated path traversal vulnerability in Cisco Catalyst SD-WAN Manager (vManage). An authenticated low-privilege user can inject path traversal sequences (e.g., `/../`, `%2e%2e%2f`, `%252e`) into REST API URLs under `/dataservice/`, causing the root-privileged vManage backend to access arbitrary host filesystem paths. Impact includes reading `/etc/shadow` (credential theft), writing to `/etc/cron.d/` (root persistence), and reading configuration databases containing tenant credentials and private keys. CISA added CVE-2026-20262 to the KEV catalog on 2026-06-15; federal deadline 2026-06-29.

False positives: legitimate API clients occasionally include encoded slashes in query parameters (not path components). Tune rule 102200 to exclude known automation tool source IPs (e.g., monitoring systems). Rule 102212 (error responses) has the lowest confidence and is informational only.

## MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| Tactic | Initial Access |
| Tactic ID | TA0001 |
| Technique | Exploit Public-Facing Application |
| Technique ID | T1190 |

Secondary techniques: T1068 (Exploitation for Privilege Escalation — traversal accesses root-owned files), T1110 (Brute Force — auth failures preceding authenticated traversal, rule 102211), T1590 (Gather Victim Network Information — API reconnaissance, rule 102204/102212)

## Lockheed Martin Kill Chain

| Phase |
|-------|
| Exploitation |
| Installation (via /etc/cron.d/ write) |

## Wazuh Rules

| Rule ID | Level | Description |
|---------|-------|-------------|
| 102200 | 13 | Path traversal sequence in /dataservice/ API request |
| 102201 | 15 | Successful (2xx) response to path traversal — exploitation likely |
| 102202 | 14 | Double-encoded traversal (%252e) — WAF evasion variant |
| 102203 | 14 | Request targeting sensitive paths (/etc/shadow, /root/, etc.) |
| 102204 | 9 | SD-WAN API version/info endpoint reconnaissance |
| 102205 | 10 | Unusual HTTP methods (PUT/DELETE/PATCH) on /dataservice/ |
| 102206 | 14 | 5+ traversal probes from same IP in 60s — automated scanner |
| 102207 | 13 | Traversal probes against multiple SD-WAN hosts — campaign |
| 102209 | 15 | Two-stage attack: traversal probe + sensitive path access |
| 102210 | 10 | Auth failure (403/401) on /dataservice/ |
| 102211 | 13 | 10+ auth failures in 60s — credential spraying |
| 102212 | 7 | Error responses from /dataservice/ — enumeration baseline |

## Splunk Detection Query

```spl
index=traefik sourcetype=json
RequestPath="/dataservice/*"
| regex RequestPath="(?i)(%2e%2e[%2f/]|\.\./|%252e|\.\.%2f|%2e%2e%5c)"
| eval traversal_success=if(DownstreamStatus>=200 AND DownstreamStatus<300, "YES", "NO")
| stats count min(_time) as firstTime max(_time) as lastTime
    values(RequestPath) as paths_probed values(DownstreamStatus) as status_codes
    by ClientHost RequestHost traversal_success
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    traversal_success="YES", 95,
    count > 10, 80,
    count > 3, 70,
    1=1, 60)
| where risk_score >= 60
| table firstTime lastTime ClientHost RequestHost paths_probed status_codes count traversal_success risk_score
| sort -risk_score
```

**Supplemental: Sensitive-path targeting**

```spl
index=traefik sourcetype=json
RequestPath="/dataservice/*"
| regex RequestPath="(?i)(etc/shadow|etc/passwd|etc/cron|root/|\.ssh/authorized_keys|proc/self)"
| stats count min(_time) as firstTime max(_time) as lastTime
    values(RequestPath) as sensitive_paths values(DownstreamStatus) as status_codes
    by ClientHost RequestHost
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=95
| table firstTime lastTime ClientHost RequestHost sensitive_paths status_codes count risk_score
```

## Risk Score Logic

| Condition | Score | Rationale |
|-----------|-------|-----------|
| Traversal + 2xx response | 95 | Exploitation confirmed: server returned content from traversed path |
| Sensitive path in traversal | 95 | Directly targeting credentials/persistence vectors |
| >10 traversal probes | 80 | Automated scanner or exploit kit |
| 3-10 traversal probes | 70 | Manual exploitation attempt |
| Single traversal probe | 60 | May be security scanner; verify source |

## Associated Threat Actors

| Actor | References |
|-------|-----------|
| UAT-8616 | Active Cisco SD-WAN campaigner — see CVE-2026-20182 predecessor |
| Opportunistic ransomware groups | Mass-scanning KEV additions within 24h of CISA notice |

## References

- [CISA KEV June 15 2026](https://www.cisa.gov/news-events/alerts/2026/06/15/cisa-adds-two-known-exploited-vulnerabilities-catalog)
- [MITRE T1190](https://attack.mitre.org/techniques/T1190/)
- [MITRE T1068](https://attack.mitre.org/techniques/T1068/)
- Related: [cisco_sdwan_auth_bypass_exploitation.md](cisco_sdwan_auth_bypass_exploitation.md) (CVE-2026-20182)
