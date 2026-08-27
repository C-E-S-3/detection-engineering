---
scraped_at: "2026-08-27T00:00:00Z"
source_url: "https://www.bleepingcomputer.com/news/security/ubiquiti-patches-three-max-severity-security-vulnerabilities/"
report_type: threat-intel
severity: high
title: "Ubiquiti Security Advisory 067: Three CVSS 10.0 CVEs in UniFi Protect, UniFi OS, and UniFi Talk (Aug 26, 2026)"
---

# Ubiquiti Security Advisory 067: Three CVSS 10.0 CVEs in UniFi Protect, UniFi OS, and UniFi Talk

**Source:** BleepingComputer (2026-08-26), Ubiquiti Security Advisory Bulletin 067 (2026-08-26)  
**Severity:** High  
**Exploitation Status:** Not yet confirmed in the wild (as of 2026-08-27)

---

## 1. IOCs

No indicators of compromise are available. Active exploitation has not been confirmed as of publication. Organizations should treat these as pre-exploitation intelligence and patch immediately given the CVSS 10.0 ratings and the remote, unauthenticated, zero-interaction exploitation profile.

---

## 2. TTPs (MITRE ATT&CK)

| Tactic | Technique ID | Technique | Usage |
|--------|-------------|-----------|-------|
| Initial Access | T1190 | Exploit Public-Facing Application | All three CVEs are remotely exploitable without authentication over the network with low attack complexity and no user interaction required |
| Execution | T1059.004 | Command and Scripting Interpreter: Unix Shell | CVE-2026-77537 and CVE-2026-77554 allow command injection via improper input validation, resulting in arbitrary OS command execution on the host device |
| Defense Evasion | T1036 | Masquerading | CVE-2026-77550 allows authentication bypass via CRLF sequence injection in HTTP headers, bypassing Ubiquiti's authentication layer without valid credentials |
| Privilege Escalation | T1068 | Exploitation for Privilege Escalation | Remote command injection may result in elevated privileges depending on the process context of UniFi Protect, UniFi OS, and UniFi Talk services |

---

## 3. Malware & Tools

No malware families associated with these CVEs at this time. The exploitation vectors are well-suited to:
- Initial access deployment of reverse shells or persistent backdoors
- Credential harvesting from UniFi management interfaces
- Network pivoting via the compromised UniFi device (Dream Machine, Cloud Gateway, Access Points)
- Integration into botnet recruitment of network edge devices (consistent with actors like Dysphoria, Mirai variants)

---

## 4. Vulnerability Details

| CVE | CVSS | Product | Affected Versions | Vulnerability Type | Description |
|-----|------|---------|------------------|--------------------|-------------|
| CVE-2026-77537 | 10.0 | UniFi Protect Application | ≤ 7.1.87 | OS Command Injection (CWE-78) | Improper input validation in the UniFi Protect Application allows remote unauthenticated command injection on the host device |
| CVE-2026-77550 | 10.0 | UniFi OS | Multiple versions | Authentication Bypass via CRLF (CWE-113) | Improper handling of CRLF sequences (`%0D%0A`) in HTTP request processing allows a remote attacker to bypass UniFi OS authentication without valid credentials |
| CVE-2026-77554 | 10.0 | UniFi Talk Application | Multiple versions | OS Command Injection (CWE-78) | Inadequate input validation in UniFi Talk's VoIP system enables remote unauthenticated command injection on the host device |

All three vulnerabilities were disclosed in **Ubiquiti Security Advisory Bulletin 067** on August 26, 2026.

---

## 5. Threat Actor / Campaign Attribution

No specific threat actor attribution. Ubiquiti devices are high-value targets for:
- **SOHO/IoT botnets**: Mirai variants, Dysphoria, and similar DDoS-for-hire botnets actively scan for and recruit Ubiquiti devices
- **China-nexus APTs**: ORB networks and similar proxy infrastructure campaigns (APT27, Volt Typhoon) target SOHO and SME network edge devices for persistence and traffic tunneling
- **Ransomware affiliates**: Network edge device compromise enables lateral movement into enterprise environments

Prior Ubiquiti exploitation (CVE-2026-34908/34909/34910) was added to CISA KEV June 23, 2026 with a 3-day remediation deadline, confirming high threat actor interest in this product family.

---

## 6. Splunk Detection Searches

### Search 1: CRLF Auth Bypass Attempts Against UniFi Management Ports (CVE-2026-77550)

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Web.Web
where Web.dest_port IN (443, 8080, 8443)
by Web.src Web.dest Web.dest_port Web.url Web.http_method Web.status Web.http_user_agent
| `drop_dm_object_name(Web)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval crlf_inject=if(match(url, "%0D|%0A|%250D|%250A|\\\\r|\\\\n"), 1, 0)
| eval cmd_inject=if(
    http_method="POST" AND match(url, "%3B|%7C|%60|%24%28|;|\\||`|\\$\\("), 1, 0)
| eval path_traversal=if(match(url, "%252F|%2F\\.\\.%2F|\\.\\./|\\.\\./"), 1, 0)
| eval exploit_type=case(
    crlf_inject=1, "crlf_auth_bypass_cve_2026_77550",
    cmd_inject=1, "cmd_injection_cve_2026_77537_77554",
    path_traversal=1, "path_traversal_legacy_cves",
    1=1, null())
| where isnotnull(exploit_type)
| eval risk_score=case(
    exploit_type="cmd_injection_cve_2026_77537_77554", 90,
    exploit_type="crlf_auth_bypass_cve_2026_77550", 85,
    exploit_type="path_traversal_legacy_cves", 80,
    1=1, 60)
| where risk_score >= 60
| table firstTime lastTime src dest dest_port url http_method status exploit_type risk_score
```

### Search 2: Suspicious Child Processes from UniFi Services Post-Exploitation

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Endpoint.Processes
where Processes.parent_process_name IN ("unifi-protect", "unifi-core", "ubios-udapi-server", "udapi-srv")
  AND Processes.process_name IN ("sh", "bash", "curl", "wget", "nc", "ncat", "python", "python3", "perl")
by Processes.dest Processes.user Processes.parent_process_name
   Processes.process_name Processes.process Processes.process_id
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=90
| table firstTime lastTime dest user parent_process_name process_name process process_id risk_score
```

---

## 7. Executive Summary

Ubiquiti published **Security Advisory Bulletin 067** on August 26, 2026, disclosing **three maximum-severity (CVSS 10.0)** vulnerabilities across its UniFi product suite. All three are remotely exploitable without authentication, require no user interaction, and are rated low in attack complexity — the ideal profile for automated exploitation campaigns.

**CVE-2026-77537** (UniFi Protect ≤ 7.1.87): Improper input validation in the video management application enables OS command injection on the host device. Attackers can execute arbitrary commands remotely without authentication.

**CVE-2026-77550** (UniFi OS): CRLF sequence injection in HTTP header processing bypasses UniFi OS authentication. This can be used to impersonate authenticated sessions, access management APIs, and chain with command injection vulnerabilities.

**CVE-2026-77554** (UniFi Talk): Inadequate input validation in the VoIP system enables remote OS command injection. The VoIP system's exposure makes this an attractive network edge attack vector.

Ubiquiti has not confirmed pre-disclosure exploitation. However, the previous Ubiquiti KEV cluster (CVE-2026-34908/34909/34910) was actively exploited at scale, and device family targeting patterns from SOHO botnet operators and nation-state ORB network builders strongly suggest rapid weaponization of these CVEs.

**Immediate actions:**
1. Update UniFi Protect to version 7.1.88 or later
2. Apply available UniFi OS and UniFi Talk updates via Ubiquiti's update channel
3. Restrict management interface (ports 443/8080/8443) access to trusted IP ranges
4. Enable network-level blocking for CRLF sequences in HTTP headers at the perimeter

---

## References

- [BleepingComputer — Ubiquiti Patches Three Max Severity Security Vulnerabilities (2026-08-26)](https://www.bleepingcomputer.com/news/security/ubiquiti-patches-three-max-severity-security-vulnerabilities/)
- [Ubiquiti Security Community — Security Advisory Bulletin 067](https://community.ui.com/releases)
- [MITRE ATT&CK — T1190: Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/)
- [MITRE ATT&CK — T1059.004: Unix Shell](https://attack.mitre.org/techniques/T1059/004/)
- [threat-intel/2026-06-23_cisa-kev-ubiquiti-unifi-os-cve-2026-34908-34909-34910.md](2026-06-23_cisa-kev-ubiquiti-unifi-os-cve-2026-34908-34909-34910.md)
- [detections/initial_access/ubiquiti_unifi_os_exploitation.md](../detections/initial_access/ubiquiti_unifi_os_exploitation.md)
