# Cisco UCM WebDialer SSRF Active Exploitation (CVE-2026-20230)

## Description

Detects exploitation of CVE-2026-20230, a high-severity server-side request forgery (SSRF) vulnerability (CVSS 8.6) in Cisco Unified Communications Manager (UCM) and UCM Session Management Edition. The vulnerability stems from inadequate validation of HTTP requests to the WebDialer service. An unauthenticated, network-adjacent attacker can send crafted HTTP requests to write files to the underlying system, potentially achieving root-level privilege escalation. CISA confirmed active exploitation in the wild as of June 23, 2026. WebDialer must be enabled (disabled by default) for exploitation.

Detection focuses on four signal layers: (1) anomalous HTTP requests to the WebDialer endpoint (`/ccmwebapi/`, `/webdialer/`) from unexpected source IPs; (2) SSRF payload indicators — internal address references (RFC1918, localhost, 169.254.x.x) or SSRF protocol schemes (gopher, dict, file) in WebDialer request parameters; (3) WebDialer probe bursts (10+ requests/60s from same source) consistent with exploit scanner activity; and (4) post-exploitation indicators — file write events from the Tomcat/CCM service user and shell process spawning from the Tomcat parent.

False positive sources: Legitimate UCM administrators testing WebDialer functionality may trigger the burst rule; internal monitoring tools probing UCM health may hit the base WebDialer endpoint. SSRF payload rules have very low false positive rates and should be treated as confirmed exploitation attempts.

## MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| Tactic | Initial Access |
| Tactic ID | TA0001 |
| Technique | Exploit Public-Facing Application |
| Technique ID | T1190 |
| Secondary Tactic | Execution |
| Secondary Technique | T1059.004 — Command and Scripting Interpreter: Unix Shell |
| Secondary Tactic | Command and Control |
| Secondary Technique | T1105 — Ingress Tool Transfer (file write to achieve payload delivery) |

## Lockheed Martin Kill Chain

| Phase |
|-------|
| Exploitation |
| Installation |
| Actions on Objectives |

## Splunk Detection Query

```spl
| comment "Query 1: WebDialer SSRF payload detection — internal address in request"
index=proxy OR index=web
(uri_path="/ccmwebapi/*" OR uri_path="/webdialer/*" OR uri_path="*/WebDialerSrv*" OR uri_path="/ccm/webdialer/*")
(uri_query="*127.0.0.1*" OR uri_query="*localhost*" OR uri_query="*169.254.169.254*"
 OR uri_query="*gopher://*" OR uri_query="*file://*" OR uri_query="*dict://*"
 OR uri_query="*10.0.*" OR uri_query="*192.168.*" OR uri_query="*172.16.*"
 OR uri_query="*172.17.*" OR uri_query="*172.18.*" OR uri_query="*172.19.*"
 OR uri_query="*172.2?.*" OR uri_query="*172.30.*" OR uri_query="*172.31.*")
| stats count min(_time) as firstTime max(_time) as lastTime by src_ip uri_path uri_query http_method http_status dest
| eval risk_score=case(
    match(uri_query,"(?i)gopher://|file://|dict://"), 95,
    match(uri_query,"(?i)169\.254\.169\.254"), 90,
    match(uri_query,"(?i)localhost|127\.0\.0\.1"), 85,
    1=1, 80)
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| table firstTime lastTime src_ip dest uri_path uri_query http_method http_status risk_score
```

```spl
| comment "Query 2: WebDialer probe burst — exploit scanner fingerprint"
index=proxy OR index=web
(uri_path="/ccmwebapi/*" OR uri_path="/webdialer/*" OR uri_path="*/WebDialerSrv*")
| bucket _time span=60s
| stats count as req_count dc(uri_path) as path_count min(_time) as firstTime max(_time) as lastTime by src_ip dest _time
| where req_count >= 10
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(req_count>=50, 90, req_count>=25, 80, 1=1, 70)
| table firstTime lastTime src_ip dest req_count path_count risk_score
```

```spl
| comment "Query 3: Post-exploitation — Tomcat/UCM service user file write in sensitive paths"
index=linux_auditd OR index=osquery
((type="CREATE" AND process_name IN ("java","tomcat","ccmservice"))
 OR (eventname="file" AND action="created" AND cmdline="java*"))
file_path IN ("*/tmp/*","*/var/tmp/*","*/etc/cron*","*/etc/init.d/*","*/root/*","*/home/*","*/.ssh/*","*/opt/cisco/*")
| stats count min(_time) as firstTime max(_time) as lastTime by dest process_name process_user file_path
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| table firstTime lastTime dest process_name process_user file_path
```

```spl
| comment "Query 4: Post-exploitation — shell spawned from Tomcat process (RCE confirmation)"
index=endpoint OR index=linux_auditd
parent_process_name IN ("java","tomcat","ccmservice","activemq")
process_name IN ("bash","sh","dash","python","python3","perl","ruby","curl","wget","nc","ncat","socat")
| stats count min(_time) as firstTime max(_time) as lastTime by dest parent_process_name process_name cmdline
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| table firstTime lastTime dest parent_process_name process_name cmdline
```

## Wazuh Detection Coverage

| Rule ID | Description | Severity |
|---------|-------------|----------|
| 103579 | WebDialer HTTP request anchor (correlation base) | 5 (Low) |
| 103580 | SSRF payload in web-log decoded WebDialer request | 13 (Critical) |
| 103581 | SSRF indicator in syslog-format UCM log | 12 (High) |
| 103582 | WebDialer probe burst (10+ req/60s, same source) | 11 (High) |
| 103583 | Tomcat/UCM service user writes file to sensitive path | 14 (Critical) |
| 103584 | Shell spawned from Tomcat parent process | 15 (Critical) |
| 103585 | Path traversal sequence in WebDialer request | 11 (High) |
| 103586 | Correlated: burst + file write within 5 minutes | 15 (Critical) |

## Risk Score Logic

- **95**: SSRF with SSRF-specific protocol (gopher/dict/file) — no benign explanation
- **90**: SSRF to metadata service (169.254.169.254) — cloud privilege escalation
- **85**: SSRF to localhost/127.0.0.1 — internal service pivoting
- **80**: SSRF to RFC1918 address — internal network reconnaissance
- **70**: Probe burst without SSRF payload — scanner fingerprint, less specific

## Associated Threat Actors

- Unknown financially-motivated threat actors (active exploitation confirmed June 23, 2026)
- VoIP/UCM infrastructure targeting has historically been associated with ransomware pre-positioning and credential harvesting for callback fraud (IRSF)

## References

- Cisco Security Advisory: cisco-sa-cucm-ssrf-cXPnHcW
- NVD: https://nvd.nist.gov/vuln/detail/CVE-2026-20230
- CVSS 8.6: AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:H/A:N
- BleepingComputer: "Cisco Unified CM Flaw CVE-2026-20230 Now Exploited in Attacks" (2026-06-23)
- Mitigation: Disable WebDialer service if not required; patch to latest UCM version
