# Xen Orchestra Empty JSON Object Cookie Authentication Bypass (VSA-2026-062)

## Description

Detects exploitation of Vates Security Advisory VSA-2026-062, a critical authentication bypass in Xen Orchestra's REST API affecting xo-server versions before 5.211.2 (stable) / 5.213.1 (latest). The REST API parsing layer converts the URL-encoded cookie value `authenticationToken=j:%7B%7D` into an empty JavaScript object `{}`, which the authentication code then accepts as a valid admin session token, granting full unauthenticated admin access to any Xen Orchestra API endpoint.

This vulnerability provides admin control over all XCP-ng pools managed by the Orchestra instance, enabling arbitrary VM operations, code execution on hypervisor hosts as root, and pool-level destructive actions. Active exploitation observed with reverse shell C2 to Tor onion address and VM creation for internal pivoting (`pivot2` label).

**Critical detection gap:** The Vates advisory explicitly states that **no authentication log entry is generated** for successful exploitation — the bypass occurs before the auth layer logs anything. Web proxy logs and network-level detection (cookie inspection, network connections) are the primary detection path.

**False positives:** Very unlikely — no legitimate client sends `authenticationToken=j:%7B%7D`. The specific URL-encoded empty JSON object is unambiguously an exploitation artifact.

## MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| Tactic | Initial Access |
| Tactic ID | TA0001 |
| Technique | Exploit Public-Facing Application |
| Technique ID | T1190 |
| Secondary Tactic | Defense Evasion (TA0005) |
| Secondary Technique | Impair Defenses — T1562.008 (exploitation generates no auth log) |
| Secondary Tactic | Command and Control (TA0011) |
| Secondary Technique | Multi-hop Proxy (Tor) — T1090.003 |
| Secondary Tactic | Persistence (TA0003) |
| Secondary Technique | Create Account / Implant Internal Image — T1136 / T1525 |

## Lockheed Martin Kill Chain

| Phase |
|-------|
| Exploitation |
| Actions on Objectives |

## Splunk Detection Query

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Web.Web
  where Web.url IN ("*/rest/v0*", "*/api/*", "*/xo-api*", "*/xo/api*")
  AND Web.status IN ("200", "201", "204")
  by Web.src Web.dest Web.url Web.http_method Web.http_user_agent Web.status
| `drop_dm_object_name(Web)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    src IN ("91.211.251.112"), 95,
    1=1, 55)
| where risk_score >= 55
| table firstTime lastTime src dest url http_method http_user_agent status count risk_score
```

**Cookie-level inspection (requires proxy logs with cookie field populated):**

```spl
index=proxy OR index=web sourcetype IN ("squid", "bluecoat", "paloalto:globalprotect", "nginx:access", "apache:access")
| rex field=_raw "Cookie: (?P<cookie_hdr>[^\r\n]+)"
| where match(cookie_hdr, "(?i)authenticationToken=j:%7B%7D")
   OR match(cookie_hdr, "authenticationToken=j:\{\}")
| rex field=_raw "(?:GET|POST|PUT|DELETE|PATCH) (?P<req_url>\S+)"
| rex field=_raw "\"(?P<src_ip>\d+\.\d+\.\d+\.\d+)\""
| stats count min(_time) as firstTime max(_time) as lastTime by src_ip req_url cookie_hdr host
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    src_ip IN ("91.211.251.112"), 95,
    1=1, 90)
| where risk_score >= 90
| table firstTime lastTime src_ip req_url host count risk_score
```

**Known attacker IP in network traffic:**

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Network_Traffic.All_Traffic
  where All_Traffic.src_ip IN ("91.211.251.112")
  OR All_Traffic.dest_ip IN ("91.211.251.112")
  by All_Traffic.src_ip All_Traffic.dest_ip All_Traffic.dest_port All_Traffic.transport
| `drop_dm_object_name(All_Traffic)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=90
| table firstTime lastTime src_ip dest_ip dest_port transport count risk_score
```

**Outbound port 3333 (Tor C2 reverse shell callback):**

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Network_Traffic.All_Traffic
  where All_Traffic.dest_port=3333
  AND All_Traffic.direction="outbound"
  by All_Traffic.src_ip All_Traffic.dest_ip All_Traffic.dest_port All_Traffic.transport All_Traffic.app
| `drop_dm_object_name(All_Traffic)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    dest_ip IN ("91.211.251.112"), 95,
    1=1, 65)
| where risk_score >= 65
| table firstTime lastTime src_ip dest_ip dest_port transport app count risk_score
```

## Risk Score Logic

| Condition | Score | Rationale |
|-----------|-------|-----------|
| Cookie contains `authenticationToken=j:%7B%7D` (any source) | 90 | No legitimate client sends this value; unambiguous exploitation artifact |
| Source IP 91.211.251.112 in any connection | 90–95 | Direct IOC match from confirmed exploitation |
| Outbound TCP 3333 from internal host | 65 | Known C2 callback port; uncommon for outbound traffic |
| Source IP 91.211.251.112 on outbound TCP 3333 | 95 | IOC + known C2 port match |

## Associated Threat Actors

| Actor | References |
|-------|-----------|
| Unattributed — Tor-anonymized actor targeting hypervisor management | Vates VSA-2026-062; TDC NET Security Nov 10 2026 |

## References

- [Vates Security Advisory VSA-2026-062](https://docs.vates.tech/security-advisories/advisories/2026/vates-sa-2026-062/)
- [The Hacker News: Hackers Exploit Critical Xen Orchestra Auth Bypass Flaw](https://thehackernews.com/2026/11/hackers-exploit-critical-xen-orchestra.html)
- [SC World: Critical authentication bypass vulnerability under active exploitation](https://www.scworld.com/brief/critical-authentication-bypass-vulnerability-in-xen-orchestra-under-active-exploitation)
- [MITRE ATT&CK T1190](https://attack.mitre.org/techniques/T1190/)
- [MITRE ATT&CK T1090.003 — Multi-hop Proxy](https://attack.mitre.org/techniques/T1090/003/)
