# SonicWall SMA1000 SSRF Active Exploitation (CVE-2026-15409)

## Description

Detects exploitation of CVE-2026-15409, a critical server-side request forgery (SSRF) vulnerability in SonicWall SMA1000 Secure Mobile Access appliances. An unauthenticated remote attacker can craft HTTP requests to the SMA1000 management or VPN API that cause the appliance to initiate outbound connections to attacker-controlled destinations, including internal RFC1918 addresses, localhost, and cloud metadata services. No authentication is required for exploitation.

CISA added CVE-2026-15409 to the Known Exploited Vulnerabilities catalog on 2026-07-14 with a federal remediation deadline of 2026-07-17.

Detection covers four signal layers:

1. **HTTP/Proxy layer**: Inbound requests to SMA1000 API endpoints containing RFC1918 addresses, localhost, or SSRF protocol schemes (gopher, dict, file) in request parameters — caught via Traefik JSON access logs.
2. **SMA1000 syslog layer**: Management daemon log messages combining SMA1000 process names with internal address or protocol references.
3. **Network/firewall layer**: Outbound connections initiated FROM the SMA1000 appliance IP to internal RFC1918 destinations — the direct result of a successful SSRF exploit.
4. **Probe burst detection**: High-frequency scanning of SMA1000 API endpoints consistent with automated exploit tooling.

False positive sources: SMA1000 legitimately connects to internal identity providers (LDAP/RADIUS), NTP servers, and certificate authorities. Baseline known-good outbound destinations and suppress confirmed legitimate connections via Wazuh rule overrides. RFC1918 addresses appearing in VPN routing API calls should be correlated with source IP and specific endpoint.

## MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| Tactic | Initial Access |
| Tactic ID | TA0001 |
| Technique | Exploit Public-Facing Application |
| Technique ID | T1190 |
| Secondary Tactic | Command and Control |
| Secondary Technique | T1071.001 — Application Layer Protocol: Web Protocols |

## Lockheed Martin Kill Chain

| Phase |
|-------|
| Reconnaissance |
| Exploitation |
| Actions on Objectives |

## Wazuh Detection Coverage

| Rule ID | Description | Severity |
|---------|-------------|----------|
| 103935 | Base anchor: HTTP request to SMA1000 management or API path (Traefik JSON) | 7 (Low) |
| 103936 | SSRF payload: RFC1918 address or SSRF protocol scheme in SMA1000 API request | 13 (Critical) |
| 103937 | SSRF to localhost or cloud metadata service — highest-confidence SSRF target | 14 (Critical) |
| 103938 | Syslog: SMA1000 management daemon log contains internal address or SSRF protocol | 12 (High) |
| 103939 | Firewall: Outbound connection from SMA1000 appliance IP to internal RFC1918 host | 11 (High) |
| 103940 | Probe burst: 10+ requests/60s from same source to SMA1000 API endpoints | 9 (Medium) |

## Splunk Detection Query

```spl
| comment "Query 1: SSRF payload in SMA1000 API request (web/proxy logs)"
index=proxy OR index=web OR index=traefik
(uri_path="*/management/*" OR uri_path="*/api/v1/*" OR uri_path="*/api/v2/*"
 OR uri_path="*/vpn/*" OR uri_path="*/cgi-bin/*" OR uri_path="*/webvpn/*"
 OR uri_path="*/cfg/*" OR uri_path="*/diagnose/*")
(uri_query="*10.*" OR uri_query="*192.168.*" OR uri_query="*172.1[6-9].*"
 OR uri_query="*172.2[0-9].*" OR uri_query="*172.3[01].*"
 OR uri_query="*127.0.0.1*" OR uri_query="*localhost*"
 OR uri_query="*169.254.169.254*"
 OR uri_query="*gopher://*" OR uri_query="*dict://*" OR uri_query="*file://*")
| stats count min(_time) as firstTime max(_time) as lastTime
    by src_ip uri_path uri_query http_method http_status dest
| eval risk_score=case(
    match(uri_query,"(?i)gopher://|dict://|file://"), 95,
    match(uri_query,"(?i)169\.254\.169\.254"), 95,
    match(uri_query,"(?i)localhost|127\.0\.0\.1"), 90,
    match(uri_query,"(?i)10\.|192\.168\.|172\.1[6-9]\.|172\.2\d\.|172\.3[01]\."), 80,
    1=1, 70)
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| table firstTime lastTime src_ip dest uri_path uri_query http_method http_status risk_score
```

```spl
| comment "Query 2: Outbound SSRF connection from SMA1000 IP to RFC1918 (firewall logs)"
index=firewall OR index=network
action IN ("allow","accept","permit","pass")
src_ip="<SMA1000_APPLIANCE_IP>"
(dest_ip="10.*" OR dest_ip="192.168.*" OR dest_ip="172.16.*" OR dest_ip="172.17.*"
 OR dest_ip="172.18.*" OR dest_ip="172.19.*" OR dest_ip="172.2*" OR dest_ip="172.30.*"
 OR dest_ip="172.31.*")
NOT (dest_port=389 OR dest_port=636 OR dest_port=1812 OR dest_port=123 OR dest_port=53)
| stats count min(_time) as firstTime max(_time) as lastTime
    by src_ip dest_ip dest_port proto
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| table firstTime lastTime src_ip dest_ip dest_port proto count
```

```spl
| comment "Query 3: SMA1000 probe burst (exploit scanner fingerprint)"
index=proxy OR index=web OR index=traefik
(uri_path="*/management/*" OR uri_path="*/api/v1/*" OR uri_path="*/api/v2/*"
 OR uri_path="*/vpn/*" OR uri_path="*/diagnose/*")
| bucket _time span=60s
| stats count as req_count dc(uri_path) as path_count
    min(_time) as firstTime max(_time) as lastTime
    by src_ip dest _time
| where req_count >= 10
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(req_count>=50, 90, req_count>=25, 80, 1=1, 70)
| table firstTime lastTime src_ip dest req_count path_count risk_score
```

## Risk Score Logic

| Condition | Score | Rationale |
|-----------|-------|-----------|
| SSRF with gopher/dict/file protocol | 95 | No benign use in SMA1000 external API |
| SSRF to cloud metadata service (169.254.169.254) | 95 | Instance credential theft in cloud deployments |
| SSRF to localhost/127.0.0.1 | 90 | Pivoting to internal SMA1000 management interfaces |
| SSRF to RFC1918 address | 80 | Internal network reconnaissance and service probing |
| Outbound connection from SMA1000 to RFC1918 (non-standard port) | 85 | Direct SSRF result; correlate with inbound request timing |
| Probe burst 50+ requests/60s | 90 | Automated exploit framework activity |
| Probe burst 10-24 requests/60s | 70 | Scanner or targeted manual reconnaissance |

## Associated Threat Actors

| Actor | Notes |
|-------|-------|
| Unknown financially-motivated actors | CISA KEV designation indicates confirmed exploitation in the wild as of 2026-07-14 |
| VPN/gateway targeting APTs | SMA1000 is a high-value target for initial access to enterprise networks |

## Remediation

1. Apply SonicWall security patches for CVE-2026-15409 immediately (federal deadline 2026-07-17)
2. If patching is not immediately possible, restrict access to SMA1000 management and API interfaces to known admin source IPs only
3. Enable egress filtering on the perimeter firewall to limit outbound connections from the SMA1000 appliance IP to only known-required destinations (identity providers, NTP, DNS)
4. Monitor Wazuh rules 103935-103940 for active exploitation indicators

## References

- CISA KEV: CVE-2026-15409 added 2026-07-14, deadline 2026-07-17
- SonicWall Security Advisory: SNWLID-2026-0023 (SMA1000 SSRF)
- NVD: CVE-2026-15409
- MITRE ATT&CK: T1190 — Exploit Public-Facing Application
- CWE-918: Server-Side Request Forgery
