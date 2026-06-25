---
scraped_at: 2026-06-22T00:00:00Z
source_url: https://blog.xlab.qianxin.com/arystinger-botnet-hijacks-legacy-routers-for-global-attacks-en/
report_type: threat-intel
severity: medium
title: "AryStinger Botnet: 4,000+ Legacy D-Link Routers and NAS Devices Turned into Global Attack Proxies (XLab, June 2026)"
---

## 1. IOCs

### Network Indicators

| Indicator | Type | Notes |
|-----------|------|-------|
| `eixfi.ajb8.com` | C2 Domain | AryStinger primary C2; identity authentication via /auth endpoint; HTTP/HTTPS with Protobuf + XOR encoding |
| `107.150.106.14` | IP Address | Initial AryStinger propagation IP; first detected spreading ELF payload via CVE-2013-3307 and CVE-2016-5681 on March 12, 2026 (VT 0-detection at time of discovery) |

### Vulnerabilities Exploited

| CVE | Product | Notes |
|-----|---------|-------|
| CVE-2013-3307 | D-Link DIR-850L | Exploited for initial compromise of legacy D-Link routers |
| CVE-2016-5681 | D-Link DIR-818LW | Stack buffer overflow exploited for initial compromise |
| CVE-2025-11837 | NAS devices (multiple vendors) | Exploited by Go-variant targeting NAS devices (detected April 26, 2026) |

---

## 2. TTPs (MITRE ATT&CK)

| Tactic | Technique ID | Technique Name | Usage |
|--------|-------------|----------------|-------|
| Initial Access | T1190 | Exploit Public-Facing Application | Exploitation of legacy router CVEs (CVE-2013-3307, CVE-2016-5681) and NAS CVE-2025-11837 |
| Execution | T1059.004 | Command and Scripting Interpreter: Unix Shell | Botnet executes system commands on compromised network devices via remote command task type |
| Persistence | T1601 | Modify System Image | Achieves persistent remote management via dropbear SSH server installation or gs-netcat |
| Command and Control | T1071.001 | Application Layer Protocol: Web Protocols | HTTP/HTTPS C2 traffic encoded with Protobuf serialization and XOR encryption |
| Command and Control | T1090 | Proxy | Converts infected devices into SOCKS5 proxy nodes for tunneling attacker traffic |
| Discovery | T1018 | Remote System Discovery | Internal and external network scanning task type; domain brute-force scanning against TLDs |
| Defense Evasion | T1036.005 | Masquerading: Match Legitimate Name or Location | Go-based NAS variant named "Ary-Attack" — designed to blend with legitimate software |
| Collection | T1040 | Network Sniffing | Silently monitors network traffic through infected devices |
| Impact | T1565 | Data Manipulation | DNS hijacking (tampers with router DNS settings to redirect victim browsing) |

---

## 3. Malware & Tools

| Name | Type | Notes |
|------|------|-------|
| AryStinger (C variant) | Botnet Agent | ELF binary targeting D-Link DIR-850L and DIR-818LW routers; exploits CVE-2013-3307 and CVE-2016-5681; self-propagates from initial seed IP 107.150.106.14 |
| AryStinger Go variant | Botnet Agent | Go-based ELF; project name "Ary-Attack"; targets NAS devices via CVE-2025-11837; more limited reach than C variant |
| dropbear | Persistence Tool | Lightweight SSH server installed on compromised devices for persistent remote management channel |
| gs-netcat | Persistence Tool | Alternative persistent channel used if dropbear is unavailable |

### Supported Botnet Task Types

- Internal/external network scanning
- Traffic tunnel forwarding and SOCKS5 proxying
- Remote system command execution
- DNS settings tampering (hijacking)
- Network traffic monitoring
- Payload delivery in Go, Java, or Python

---

## 4. Threat Actor / Campaign Attribution

No specific threat actor attribution identified by XLab. The campaign appears to be financially motivated or criminal infrastructure (proxy service for hire). The research was published following a Chinese Ministry of State Security article (May 20, 2026) that highlighted outdated routers as cybersecurity entry points.

**Geographic distribution of infected devices:**
- South Korea: 48.5%
- China: 31.8%
- Sweden: 6.4%
- Malaysia: 3.5%
- Singapore: 2.5%

---

## 5. Splunk Detection Searches

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Network_Traffic.All_Traffic
where All_Traffic.dest_ip IN ("107.150.106.14")
   OR All_Traffic.dest IN ("eixfi.ajb8.com")
by All_Traffic.src All_Traffic.dest All_Traffic.dest_ip All_Traffic.dest_port All_Traffic.action
| `drop_dm_object_name(All_Traffic)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=90
| table firstTime lastTime src dest dest_ip dest_port action risk_score
```

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Network_Resolution.DNS
where DNS.query IN ("eixfi.ajb8.com","ajb8.com")
by DNS.src DNS.query DNS.answer
| `drop_dm_object_name(DNS)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=85
| table firstTime lastTime src query answer risk_score
```

---

## 6. Executive Summary

XLab (Qianxin) disclosed the **AryStinger** botnet in June 2026 after detecting it spreading from IP `107.150.106.14` on March 12, 2026 — at which point the ELF payload had zero VirusTotal detections. The botnet exploits years-old, unpatched CVEs in legacy D-Link routers (DIR-850L: CVE-2013-3307; DIR-818LW: CVE-2016-5681) and a 2025 NAS vulnerability (CVE-2025-11837). Over 4,000 devices have been compromised, predominantly in South Korea and China.

Infected devices are converted into multi-purpose attack proxies: they perform network scanning, SOCKS5 traffic tunneling, DNS hijacking, and arbitrary command execution on behalf of the botnet operator. C2 traffic is encoded with Protobuf and XOR encryption over HTTP/HTTPS to `eixfi.ajb8.com`. Persistence is established via dropbear SSH server or gs-netcat remote management channels.

Organizations should block `eixfi.ajb8.com` and the initial seed IP `107.150.106.14` in DNS and firewall controls. Any legacy D-Link DIR-850L or DIR-818LW routers still in use should be replaced immediately as no vendor patches are forthcoming for end-of-life devices.

---

## References

- [XLab Qianxin — AryStinger Botnet (June 2026)](https://blog.xlab.qianxin.com/arystinger-botnet-hijacks-legacy-routers-for-global-attacks-en/)
- [BleepingComputer — AryStinger botnet infected thousands of D-Link routers worldwide](https://www.bleepingcomputer.com/news/security/arystinger-botnet-infected-thousands-of-d-link-routers-worldwide/)
- [MITRE ATT&CK — T1190: Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/)
- [NVD — CVE-2013-3307](https://nvd.nist.gov/vuln/detail/CVE-2013-3307)
- [NVD — CVE-2016-5681](https://nvd.nist.gov/vuln/detail/CVE-2016-5681)
