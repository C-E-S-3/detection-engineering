# PAN-OS GlobalProtect Authentication Override Cookie Bypass (CVE-2026-0257)

## Description

Detects exploitation of CVE-2026-0257, an authentication bypass (CVSS 7.8) in Palo Alto Networks PAN-OS affecting GlobalProtect portal and gateway. When a TLS certificate is shared between GlobalProtect and another PAN-OS feature (e.g., the HTTPS or SSL-VPN interface), an unauthenticated attacker can retrieve the certificate's public key from the co-hosted feature and use it to forge arbitrary GlobalProtect **authentication override cookies**, bypassing all authentication controls without credentials.

Active exploitation was confirmed by Rapid7 MDR on May 29, 2026. Two exploitation waves were observed originating from VPS infrastructure (Vultr, Dromatics Systems), both using a spoofed MAC address (`aa:bb:cc:dd:ee:ff`) and generic machine names (`GP-CLIENT`, `DESKTOP-GP01`). CISA added CVE-2026-0257 to the Known Exploited Vulnerabilities catalog on May 29, 2026.

**Vulnerable configuration (both conditions must be true):**
1. GlobalProtect portal or gateway has authentication override cookies enabled.
2. The TLS certificate used by GlobalProtect is also used by another PAN-OS feature.

**False positives:** Cookie-based GlobalProtect auth from legitimate remote users is normal when auth override is intentionally deployed. Tune Search 1 against a lookup of known-good employee device names and source IPs. Search 2 (volume-based) will fire for users with flapping VPN connections; set the threshold appropriate for your environment.

## MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| Tactic | Initial Access |
| Tactic ID | TA0001 |
| Technique | Exploit Public-Facing Application |
| Technique ID | T1190 |

Secondary technique: T1550.004 (Use Alternate Authentication Material: Web Session Cookie) — the forged override cookie is the mechanism granting bypass access.

## Lockheed Martin Kill Chain

| Phase |
|-------|
| Delivery |
| Exploitation |

## Splunk Detection Query

```spl
| comment "Search 1: GlobalProtect cookie auth with known attacker machine names (CVE-2026-0257)"
`pan_firewall` log_type=globalprotect eventid=connected
| eval auth_method=coalesce(auth, authentication_method, "unknown")
| where auth_method="cookie"
| stats count
    dc(machine) as distinct_machines
    values(machine) as machine_names
    values(src) as src_ips
    min(_time) as firstTime max(_time) as lastTime
  by user dest
| eval suspicious_machine=if(
    match(mvjoin(machine_names,"|"),"(?i)(^gp-client$|^desktop-gp\d+$)"),
    "yes","no")
| eval risk_score=case(
    suspicious_machine="yes", 90,
    distinct_machines >= 3, 80,
    count >= 10, 65,
    1=1, 50)
| where risk_score >= 50
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| table firstTime lastTime user dest auth_method machine_names src_ips distinct_machines count risk_score
```

```spl
| comment "Search 2: High-rate GlobalProtect auth events from single source — reconnaissance or cookie replay attempt"
`pan_firewall` log_type=globalprotect
  (eventid=auth-failure OR eventid=connected OR eventid=login)
| bucket _time span=5m
| stats count
    dc(eventid) as event_types
    values(eventid) as event_ids
    values(machine) as machines
  by src user dest _time
| where count >= 10
| eval risk_score=case(count >= 30, 85, count >= 20, 75, count >= 10, 60, 1=1, 40)
| where risk_score >= 60
| `security_content_ctime(_time)`
| table _time src user dest event_ids machines count risk_score
```

```spl
| comment "Search 3: GlobalProtect VPN sessions from VPS/data-center ASN — attacker staging infrastructure"
`pan_firewall` log_type=globalprotect eventid=connected
| iplocation src
| where match(Org,"(?i)vultr|dromatics|digital.?ocean|linode|amazon|azure|google|hetzner|ovh")
| stats count values(machine) as machines min(_time) as firstTime max(_time) as lastTime
  by src user Org dest
| eval risk_score=85
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| table firstTime lastTime src user Org dest machines count risk_score
```

## Risk Score Logic

| Condition | Score | Rationale |
|-----------|-------|-----------|
| Cookie auth + machine name matching `GP-CLIENT` or `DESKTOP-GP{n}` pattern | 90 | Known attacker machine names from confirmed May 2026 exploitation; near-certain true positive |
| Cookie auth + 3 or more distinct machine names from same user/gateway | 80 | Multiple machines auth'ing via override cookie from one identity; strongly anomalous |
| Cookie auth + 10 or more auth events in session window | 65 | Elevated auth volume with cookie method; may indicate automated forged-cookie replay |
| New VPN session from VPS/data-center ASN (Vultr, Dromatics, etc.) | 85 | Attackers used VPS infrastructure in both observed exploitation waves; legitimate users rarely VPN from cloud datacenter IPs |
| 10–29 auth events (login/failure/connected) from single source in 5 min | 60 | Rapid auth sequence consistent with cookie enumeration or replay scanning |

## Associated Threat Actors

| Actor | References |
|-------|-----------|
| Unknown (unattributed, likely single threat actor) | [Rapid7 ETR CVE-2026-0257](https://www.rapid7.com/blog/post/etr-rapid7-observed-exploitation-of-pan-os-globalprotect-authentication-bypass-vulnerability-cve-2026-0257/) |
| CL-STA-1132 (state-sponsored, for related PAN-OS pattern) | [Unit 42 — CVE-2026-0300](https://unit42.paloaltonetworks.com/captive-portal-zero-day/) |

## References

- [Rapid7 ETR — CVE-2026-0257 Observed Exploitation (2026-05-29)](https://www.rapid7.com/blog/post/etr-rapid7-observed-exploitation-of-pan-os-globalprotect-authentication-bypass-vulnerability-cve-2026-0257/)
- [Palo Alto Networks Security Advisory CVE-2026-0257](https://security.paloaltonetworks.com/CVE-2026-0257)
- [CISA KEV — CVE-2026-0257](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
- [The Hacker News — CVE-2026-0257 Under Active Exploitation](https://thehackernews.com/2026/05/pan-os-globalprotect-authentication.html)
- [MITRE ATT&CK T1190 — Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/)
- [MITRE ATT&CK T1550.004 — Use Alternate Authentication Material: Web Session Cookie](https://attack.mitre.org/techniques/T1550/004/)
