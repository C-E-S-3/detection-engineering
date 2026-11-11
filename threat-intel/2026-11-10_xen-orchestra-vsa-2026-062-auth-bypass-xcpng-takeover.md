---
scraped_at: 2026-11-10T00:00:00Z
source_url: https://docs.vates.tech/security-advisories/advisories/2026/vates-sa-2026-062/
report_type: threat-intel
severity: critical
title: "Xen Orchestra VSA-2026-062: Empty JSON Cookie Auth Bypass — Active XCP-ng Takeover"
---

# Xen Orchestra VSA-2026-062: Empty JSON Cookie Auth Bypass — Active XCP-ng Takeover

**Source:** Vates Security Advisory VSA-2026-062 / The Hacker News / SC World  
**Published:** 2026-11-10  
**Severity:** Critical (no CVSS assigned; vendor rates Critical)

---

## 1. IOCs

### IP Addresses

| Indicator | Type | First Seen | Context |
|-----------|------|------------|---------|
| 91.211.251[.]112 | IPv4 | 2026-11-10 | Xen Orchestra VSA-2026-062 exploitation source IP; active exploitation of empty JSON object cookie auth bypass; observed on port 8001 (Vates advisory) |

### Onion Services (Tor)

| Indicator | Type | Context |
|-----------|------|---------|
| ustar3rqxgnskzgnwkgpofgtvxevm6cx3lxdbwt4mndtveqyaohid[.]onion:3333 | Tor hidden service | Xen Orchestra VSA-2026-062 attacker C2 — reverse shell callback observed calling out to this Tor address (Vates advisory) |

### Pivot VM Indicator

Attackers were observed creating a virtual machine labeled **`pivot2`** within compromised XCP-ng pools to establish internal footholds. Administrators should audit VM inventories for unrecognized VMs with suspicious names.

### Advisory

| Advisory | Vendor | No CVE assigned | Affected | Fixed |
|----------|--------|-----------------|----------|-------|
| VSA-2026-062 | Vates (Xen Orchestra / XCP-ng) | — | xo-server < 5.211.2 (stable); xo-server < 5.213.1 (latest) | Xen Orchestra 6.9.2 (stable) / 6.10.1 (latest) |

---

## 2. TTPs (MITRE ATT&CK)

| Tactic | Technique | Notes |
|--------|-----------|-------|
| TA0001 Initial Access | T1190 — Exploit Public-Facing Application | Empty JSON object cookie bypasses REST layer authentication on exposed Xen Orchestra instances |
| TA0006 Credential Access | T1539 — Steal Web Session Cookie | Exploitation retrieves reusable login tokens from the session store post-bypass |
| TA0002 Execution | T1059 — Command and Scripting Interpreter | Arbitrary code execution on XCP-ng host as root via hypervisor management API |
| TA0003 Persistence | T1525 — Implant Internal Image / T1136 — Create Account | Attackers created VM labeled `pivot2` as an internal foothold; session tokens may persist |
| TA0005 Defense Evasion | T1562.008 — Disable or Modify Cloud Logs | Advisory notes no detection log exists for unauthenticated access to the REST API — exploitation leaves no auth-layer evidence |
| TA0011 Command and Control | T1090.003 — Multi-hop Proxy (Tor) | Reverse shell callbacks to Tor hidden service ustar3rqxgnskzgnwkgpofgtvxevm6cx3lxdbwt4mndtveqyaohid.onion:3333 |

**Kill Chain Phase:** Exploitation — hypervisor-level code execution via auth bypass; Actions on Objectives — unauthorized VM creation, internal pivoting

---

## 3. Malware & Tools

No named malware family attributed. Attack chain uses native Xen Orchestra REST API functionality post-auth-bypass. The Tor C2 endpoint and pivot VM creation indicate a manual or semi-automated operation rather than automated ransomware. The reverse shell callback pattern is consistent with hands-on-keyboard post-exploitation.

---

## 4. Threat Actor / Campaign Attribution

No threat actor formally attributed. Vates confirmed active exploitation in the wild at time of advisory publication (November 10, 2026). Exploitation appears targeted at hypervisor management infrastructure rather than broad opportunistic scanning, given the deliberate pivot VM creation. The Tor C2 infrastructure suggests the operator values anonymity. Researchers Filip Magic and Christoffer Olsen (TDC NET Security) reported the vulnerability.

---

## 5. Splunk Detection Searches

### 5.1 Xen Orchestra Empty JSON Object Cookie Authentication Bypass

Detects HTTP requests to the Xen Orchestra REST API bearing the `authenticationToken=j:%7B%7D` cookie (URL-decoded: `{}`), which is the exploitation trigger for VSA-2026-062.

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Web.Web
  where Web.url IN ("*/rest/v0*", "*/api/*", "*/xo-api*")
  AND Web.status IN ("200", "201", "204")
  by Web.src Web.dest Web.url Web.http_method Web.http_user_agent Web.cookie Web.status
| `drop_dm_object_name(Web)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| where match(cookie, "(?i)authenticationToken=j:%7B%7D") OR match(cookie, "authenticationToken=j:\{\}")
| eval risk_score=case(
    src IN ("91.211.251.112"), 95,
    1=1, 90)
| where risk_score >= 90
| table firstTime lastTime src dest url http_method http_user_agent cookie status count risk_score
```

### 5.2 Known Xen Orchestra Attacker IP in Web Traffic

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Network_Traffic.All_Traffic
  where All_Traffic.dest_ip IN ("91.211.251.112")
  OR All_Traffic.src_ip IN ("91.211.251.112")
  by All_Traffic.src_ip All_Traffic.dest_ip All_Traffic.dest_port All_Traffic.transport
| `drop_dm_object_name(All_Traffic)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=90
| table firstTime lastTime src_ip dest_ip dest_port transport count risk_score
```

### 5.3 Reverse Shell Outbound to Tor from Hypervisor Host

Detects outbound TCP connections on port 3333 from hypervisor management hosts, particularly to Tor relay IPs, consistent with the VSA-2026-062 post-exploitation callback pattern.

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Network_Traffic.All_Traffic
  where All_Traffic.dest_port=3333
  AND All_Traffic.direction="outbound"
  by All_Traffic.src_ip All_Traffic.src_port All_Traffic.dest_ip All_Traffic.dest_port All_Traffic.app
| `drop_dm_object_name(All_Traffic)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    dest_ip IN ("91.211.251.112"), 95,
    1=1, 70)
| where risk_score >= 70
| table firstTime lastTime src_ip src_port dest_ip dest_port app count risk_score
```

### 5.4 Unauthorized VM Creation in XCP-ng Pool (Pivot Foothold Detection)

Detects VM creation events in XenServer/XCP-ng audit logs where the creator is not an expected administrative account — consistent with the `pivot2` VM creation pattern.

```spl
index=virtualization sourcetype IN ("xcp-ng", "xenserver", "xen-orchestra-audit")
| rex field=_raw "action=(?P<xo_action>\S+)"
| rex field=_raw "user=(?P<xo_user>\S+)"
| rex field=_raw "VM_name=(?P<vm_name>[^\s\]]+)"
| where xo_action IN ("VM.create", "VM.clone", "VM.copy", "createVm")
| stats count min(_time) as firstTime max(_time) as lastTime by xo_user vm_name host
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    match(vm_name, "(?i)pivot"), 95,
    NOT match(xo_user, "(?i)(admin|xo-admin|system)"), 80,
    1=1, 65)
| where risk_score >= 65
| table firstTime lastTime xo_user vm_name host count risk_score
```

---

## 6. Executive Summary

Vates published VSA-2026-062 on November 10, 2026, disclosing an authentication bypass in Xen Orchestra's REST API that is actively exploited in the wild. The flaw resides in how the REST layer parses authentication cookies: the string `authenticationToken=j:%7B%7D` URL-decodes to an empty JSON object `{}`, which the authentication code accepts as a valid (admin-equivalent) session token. An unauthenticated attacker can send this cookie to any exposed Xen Orchestra API endpoint and receive full admin access, including the ability to issue commands to any XCP-ng pool managed by that Orchestra instance. Because exploitation occurs at the REST parsing layer, **no authentication log entry is generated** — the advisory explicitly warns that unauthenticated access via this method is undetectable from auth logs alone. Observed attacker behavior includes extracting reusable login tokens, executing arbitrary code on XCP-ng hosts as root, creating a VM named `pivot2` as an internal foothold, and establishing C2 via reverse shell to a Tor hidden service (ustar3rqxgnskzgnwkgpofgtvxevm6cx3lxdbwt4mndtveqyaohid[.]onion:3333). Operators should immediately upgrade to Xen Orchestra 6.9.2 (stable) or 6.10.1 (latest), block `91.211.251.112`, rotate all credentials, and audit VM inventories for unauthorized VMs.

---

## References

- [Vates Security Advisory VSA-2026-062](https://docs.vates.tech/security-advisories/advisories/2026/vates-sa-2026-062/)
- [The Hacker News: Hackers Exploit Critical Xen Orchestra Auth Bypass Flaw](https://thehackernews.com/2026/11/hackers-exploit-critical-xen-orchestra.html)
- [SC World: Critical authentication bypass vulnerability in Xen Orchestra under active exploitation](https://www.scworld.com/brief/critical-authentication-bypass-vulnerability-in-xen-orchestra-under-active-exploitation)
- [WindowsForum: Xen Orchestra Authentication Bypass Exploited](https://windowsforum.com/news/xen-orchestra-authentication-bypass-exploited-patch-xcp-ng-management-servers-and-check-for-compromise.451676/)
