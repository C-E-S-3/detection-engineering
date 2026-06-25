---
scraped_at: 2026-06-24T00:00:00Z
source_url: multiple — see references
report_type: threat-intel-batch
severity: high
title: "Wazuh Rules Batch: AryStinger D-Link/NAS Botnet + Icarus/Klue OAuth Salesforce CRM Breach (2026-06-24)"
---

## Summary

Detection rules (Wazuh XML, IDs 103541–103557) for two threat intelligence items from
2026-06-22 threat-intel commits that were not covered in the previous PR #35 batch.

## Threats Covered

### 1. AryStinger Botnet — Rules 103541–103549

**Source:** XLab Qianxin, June 2026  
**Severity:** Medium  
**CVEs exploited:** CVE-2013-3307 (D-Link DIR-850L), CVE-2016-5681 (D-Link DIR-818LW), CVE-2025-11837 (NAS — Go variant)

D-Link router and NAS botnet converting 4,000+ legacy devices into multi-purpose attack
infrastructure. Propagated from seed IP `107.150.106.14` beginning March 12, 2026 with
zero VirusTotal detections. C2 at `eixfi.ajb8.com` using Protobuf+XOR encoding over HTTP/S.

Infected devices are weaponized for SOCKS5 traffic proxying, network scanning, DNS
hijacking, and arbitrary command execution. Persistence established via dropbear SSH server
or gs-netcat remote management channels.

**IOCs:**
- C2 domain: `eixfi.ajb8.com`
- Propagation IP: `107.150.106.14`

**TTPs:** T1190, T1601, T1090, T1071.001, T1565, T1040

**Rules 103541–103549:**
- `103541` T1190/T1071.001: Outbound firewall hit to AryStinger propagation IP `107.150.106.14`
- `103542` T1190: Inbound from AryStinger IP (active exploit attempt against our devices)
- `103543` T1071.001/T1090: DNS query for AryStinger C2 `eixfi.ajb8.com` (Unbound/dnsmasq)
- `103544` T1071.001: Suricata DNS EVE match on `eixfi.ajb8.com`
- `103545` T1190: Suricata traffic to AryStinger propagation IP
- `103546` T1601/T1021.004: dropbear SSH server execution (botnet persistence)
- `103547` T1601/T1090: gs-netcat execution (alternative botnet persistence)
- `103548` T1565: DNS config change on network device syslog (DNS hijacking)
- `103549` T1190/T1090: **CRITICAL** — Correlation: multiple AryStinger IOC signals within 5 minutes

### 2. Icarus / Klue OAuth / Salesforce CRM Breach — Rules 103550–103557

**Source:** Datadog Security Labs + Huntress, June 2026  
**Severity:** High  
**Actor:** Icarus extortion group (possible ShinyHunters / UNC6240 affiliation)

Beginning June 11, 2026, Icarus exploited a dormant, never-decommissioned OAuth credential
in Klue's integration backend to generate OAuth refresh tokens for connected customer
Salesforce instances. Automated Python scripts (Python-urllib/3.12 and /3.14) extracted
bulk CRM records (Opportunity, Case, Contact, Account, User, Contract, etc.) using up to
1,000 Salesforce API queries per 15-minute window and QueryMore to bypass the 2,000-record
limit. Confirmed victims include Huntress, Recorded Future, Tanium, Jamf, Sprout Social,
Gong, and Insurity.

**Attacker IPs:**
- `138.226.246.94`
- `212.86.125.24`
- `213.111.148.90`
- `94.154.32.160`

**TTPs:** T1078.004, T1213, T1530, T1567, T1059.006, T1657

**Rules 103550–103557:**
- `103550` T1078.004/T1213: Firewall hit from Icarus IP `138.226.246.94`
- `103551` T1078.004/T1530: Firewall hit from Icarus IP `212.86.125.24`
- `103552` T1078.004/T1567: Firewall hit from Icarus IP `213.111.148.90`
- `103553` T1078.004/T1567: Firewall hit from Icarus IP `94.154.32.160`
- `103554` T1078.004: Suricata match on any of the 4 Icarus IPs
- `103555` T1059.006/T1213: `Python-urllib/3.1x` user-agent in web/proxy logs
- `103556` T1213/T1530: High-volume API burst (200+ requests in 15 minutes, same source)
- `103557` T1078.004/T1213: **CRITICAL** — Correlation: Icarus IOC IP + Python-urllib automation

## Rule ID Range

`103541–103557` (17 rules). **Next available: `103558`.**

## IOCs Status

IOCs already added to CSV files in commits `594e68af` (2026-06-22) and `3743966` (2026-06-23):
- `iocs/ip.csv`: AryStinger `107.150.106.14` and all 4 Icarus IPs
- `iocs/domain.csv`: AryStinger `eixfi.ajb8.com`

No IOC CSV updates required for this PR.

## Deployment Notes

- **AryStinger DNS rules (103543, 103544):** Require OPNsense Unbound syslog forwarding or Suricata DNS events flowing to Wazuh.
- **AryStinger persistence rules (103546, 103547):** Require auditd `execve` monitoring on Linux hosts (already deployed via inframan auditd templates).
- **AryStinger DNS hijacking rule (103548):** Requires network device syslog forwarding to Wazuh with hostname fields matching `opnsense|pfsense|router|gateway|nas|synology|qnap`.
- **Icarus web rules (103555, 103556):** Require Traefik/nginx access logs forwarded to Wazuh with `http_user_agent` field decoded.
- **All firewall rules (103541, 103542, 103550–103553):** Fire on OPNsense/pf syslog forwarded to Wazuh with `data.dest_ip`/`data.src_ip` fields.

## References

- [XLab Qianxin — AryStinger Botnet (June 2026)](https://blog.xlab.qianxin.com/arystinger-botnet-hijacks-legacy-routers-for-global-attacks-en/)
- [Datadog Security Labs — Klue/Salesforce Supply Chain Attack](https://securitylabs.datadoghq.com/articles/detecting-the-klue-supply-chain-attack-in-salesforce/)
- [MITRE ATT&CK — T1190: Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/)
- [MITRE ATT&CK — T1601: Modify System Image](https://attack.mitre.org/techniques/T1601/)
- [MITRE ATT&CK — T1078.004: Valid Accounts: Cloud Accounts](https://attack.mitre.org/techniques/T1078/004/)
- [MITRE ATT&CK — T1213: Data from Information Repositories](https://attack.mitre.org/techniques/T1213/)
- [MITRE ATT&CK — T1090: Proxy](https://attack.mitre.org/techniques/T1090/)
