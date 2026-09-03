# SonicWall SMA1000 SSRF to OS Command Injection (CVE-2026-83548 / CVE-2026-83549)

## Description

Detects exploitation of CVE-2026-83548 and CVE-2026-83549, a chained zero-day delivering unauthenticated remote code execution on SonicWall SMA1000 enterprise remote-access appliances. Active exploitation confirmed September 1–2, 2026; CISA KEV added September 2, 2026.

CVE-2026-83548 (CVSS 10.0) is a Server-Side Request Forgery in the public-facing WorkPlace portal. An unauthenticated attacker sends a crafted request to WorkPlace, which proxies it to the internal-only Appliance Management Console (AMC) bound to localhost — bypassing network-layer controls. CVE-2026-83549 (CVSS 7.8) is an OS command injection in AMC that, under normal conditions, requires admin authentication; the SSRF chain makes AMC reachable as if from localhost, bypassing the authentication requirement. The result is fully unauthenticated root-level code execution on the appliance.

**Affected models**: SMA1000 6210, 7210, 8200v. NOT affected: SMA 100 Series, SonicWall firewall SSL-VPN.

**Note**: This detection covers the September 2026 CVE pair. The July 2026 SMA1000 CVE pair (CVE-2026-15409 / CVE-2026-15410) is covered by `sonicwall_sma1000_ssrf_rce_exploitation.md`.

**False positive sources:**
- Legitimate administrative access to WorkPlace or AMC from management systems should have consistent source IPs from management subnets; tune by IP allowlist
- Vulnerability scanners may probe the WorkPlace endpoint; exclude known scanner IPs

## MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| Tactic | Initial Access |
| Tactic ID | TA0001 |
| Technique | Exploit Public-Facing Application |
| Technique ID | T1190 |
| Secondary Tactic | Execution |
| Secondary Technique | Command and Scripting Interpreter: Unix Shell (T1059.004) |

## Lockheed Martin Kill Chain

| Phase |
|-------|
| Exploitation |

## Splunk Detection Query

### Query 1: Suspicious WorkPlace Requests Containing AMC Endpoint Paths

Detects HTTP requests to the SonicWall SMA1000 WorkPlace interface where URL parameters contain internal AMC endpoint paths — the core indicator of SSRF exploitation (CVE-2026-83548).

```spl
index=* (sourcetype=access_combined OR sourcetype=nginx:access OR sourcetype=traefik:access OR sourcetype=sonicwall:sma OR sourcetype=pan:traffic)
(uri="*/workplace/*" OR uri="*/WorkPlace/*" OR dest_port=443 OR dest_port=8443)
(uri_query="*/cgi-bin/amc*" OR uri_query="*/cgi-bin/management*" OR uri_query="*amc*" OR
 form_data="*/cgi-bin/amc*" OR form_data="*localhost*" OR form_data="*127.0.0.1*")
| eval ssrf_indicator=if(match(uri_query,"cgi-bin/amc|cgi-bin/management|localhost|127\.0\.0\.1") OR
    match(form_data,"cgi-bin/amc|cgi-bin/management|localhost|127\.0\.0\.1"), "true", "false")
| where ssrf_indicator="true"
| stats count min(_time) as firstTime max(_time) as lastTime values(src_ip) as source_ips values(uri) as uri_list values(uri_query) as query_list by dest host
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=95
| table firstTime lastTime host dest source_ips uri_list query_list count risk_score
```

### Query 2: Web Data Model — Suspicious POST to WorkPlace with Shell Metacharacters

Detects POST requests to the SonicWall WorkPlace interface containing OS command injection metacharacters — consistent with CVE-2026-83549 exploitation routed through CVE-2026-83548 SSRF.

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
    values(Web.src) as source_ips values(Web.uri_path) as uri_list values(Web.uri_query) as query_list
    from datamodel=Web.Web
    where (Web.uri_path="*/workplace/*" OR Web.uri_path="*/WorkPlace/*" OR Web.uri_path="*/cgi-bin/amc*")
    AND Web.http_method=POST
    by Web.dest Web.uri_path
| `drop_dm_object_name(Web)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| search query_list="*;*" OR query_list="*|*" OR query_list="*`*" OR query_list="*$(*" OR query_list="*&&*" OR query_list="*>*"
| eval risk_score=95
| table firstTime lastTime dest uri_list query_list source_ips count risk_score
```

### Query 3: Unexpected Outbound Connections from SMA1000 Appliance (Post-Exploitation)

Detects unusual outbound network connections from an SMA1000 appliance — consistent with post-exploitation reverse shell or beacon activity. Requires network flow or firewall log visibility on the appliance's management or data plane interface.

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
    values(All_Traffic.dest_ip) as dest_ips values(All_Traffic.dest_port) as dest_ports
    from datamodel=Network_Traffic.All_Traffic
    where All_Traffic.src_category="sonicwall_sma" OR All_Traffic.src_zone="sma_appliance"
    AND NOT (All_Traffic.dest_port IN (443, 80, 53, 123, 8443))
    AND NOT All_Traffic.dest_ip IN ("10.0.0.0/8","172.16.0.0/12","192.168.0.0/16")
    by All_Traffic.src_ip All_Traffic.src_zone
| `drop_dm_object_name(All_Traffic)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    mvcount(dest_ports) > 3, 90,
    1=1, 80)
| where risk_score >= 80
| table firstTime lastTime src_ip src_zone dest_ips dest_ports count risk_score
```

## Risk Score Logic

| Condition | Score | Rationale |
|-----------|-------|-----------|
| WorkPlace request with AMC path in parameters | 95 | Direct SSRF exploitation indicator; no benign explanation for AMC paths in WorkPlace query strings |
| POST to WorkPlace/AMC with shell metacharacters | 95 | Command injection attempt; immediate response required |
| Unexpected outbound connections from SMA appliance (multiple ports) | 90 | Post-exploitation C2 or reverse shell activity |
| Unexpected outbound connections from SMA appliance (single port) | 80 | Possible post-exploitation; investigate immediately |

## Associated Threat Actors

| Actor | References |
|-------|-----------|
| Unknown opportunistic actors | CISA KEV September 2, 2026; exploitation observed prior to patch availability |
| Likely initial access brokers | SMA1000 compromise provides persistent VPN-level network access; high resale value |
| Suspected nation-state aligned actors | Pattern consistent with prior SonicWall targeting by UNC2630/APT5 (CISA advisory AA22-257A) |

## References

- [SonicWall Security Advisory — CVE-2026-83548/83549](https://psirt.global.sonicwall.com/vuln-detail/SNWLID-2026-0019)
- [CISA KEV Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
- [NVD CVE-2026-83548](https://nvd.nist.gov/vuln/detail/CVE-2026-83548)
- [NVD CVE-2026-83549](https://nvd.nist.gov/vuln/detail/CVE-2026-83549)
- [BleepingComputer — SonicWall SMA1000 Zero-Day Exploited in Wild](https://www.bleepingcomputer.com/news/security/sonicwall-sma1000-zero-day-exploited/)
- [CISA Advisory AA22-257A — APT5 Targeting of Pulse Connect Secure / SonicWall](https://www.cisa.gov/uscert/ncas/alerts/aa22-257a)
- [MITRE ATT&CK T1190 — Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/)
- [MITRE ATT&CK T1059.004 — Unix Shell](https://attack.mitre.org/techniques/T1059/004/)
