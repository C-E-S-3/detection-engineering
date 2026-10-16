---
scraped_at: "2026-10-16T00:00:00Z"
source_url: "https://unit42.paloaltonetworks.com/ai-campaign-targets-linux-infrastructure/"
report_type: threat-intel
severity: high
title: "CL-UNK-1211: Suspected AI-Assisted Espionage Campaign Targeting Government Linux Infrastructure"
---

# CL-UNK-1211: Suspected AI-Assisted Espionage Campaign Targeting Government Linux Infrastructure

**Published:** 2026-10-15  
**Source:** Palo Alto Networks Unit 42  
**Severity:** High  
**Actor:** CL-UNK-1211 (unattributed cluster)  
**Nexus:** Unknown; targets suggest state-nexus espionage  

> **Note on IOC coverage:** The Unit 42 article was inaccessible for direct scraping at the time of ingestion (DNS policy restrictions in the collection environment). TTP and campaign details below are derived from publicly available summaries. No file hashes, IPs, or domains have been added to the IOC CSVs for this item, as the source article could not be directly accessed to verify concrete indicator values. Analysts should consult the source URL directly for IOC lists.

---

## Executive Summary

Unit 42 published research on October 15, 2026 describing CL-UNK-1211, a suspected espionage threat cluster active from October 2025 through at least April 2026. The campaign targeted government Linux server infrastructure, deploying a custom Go backdoor (SysGoRAT) and PHP webshells via `auto_prepend_file` hijacking. A notable characteristic of the campaign is the presence of step-by-step reasoning comments embedded in attacker-authored scripts, which Unit 42 assesses may indicate AI-assisted code generation — though autonomous AI agent operation was not confirmed.

---

## Campaign Timeline

| Date | Activity |
|------|----------|
| October 2025 | Earliest observed campaign activity |
| October 2025 – April 2026 | Main campaign window targeting government Linux servers |
| October 15, 2026 | Unit 42 public disclosure |

---

## Malware and Tooling

### SysGoRAT

A custom backdoor written in Go, deployed as the primary persistent access mechanism on compromised Linux servers. No publicly disclosed hash values at time of ingestion.

### PHP Webshells via `auto_prepend_file`

Webshells were persisted using PHP's `auto_prepend_file` configuration directive, which causes a specified PHP file to be automatically executed before every PHP script on the server. This technique:
- Provides persistence without modifying legitimate PHP application files
- Survives application upgrades and file integrity checks that only monitor application directories
- Requires modification of `php.ini`, `.user.ini`, or `.htaccess` to configure the directive

### Credential Theft Mechanisms

- **`.bashrc` hijacking:** Malicious code injected into shell initialization files to capture credentials at login
- **PHP login page modifications:** Legitimate login forms modified to exfiltrate credentials to actor-controlled infrastructure

---

## Lateral Movement

| Technique | Description |
|-----------|-------------|
| SSH double-hop | Lateral movement via SSH using stolen credentials, chaining through intermediate hosts |
| MSSQL double-hop | Lateral movement via Microsoft SQL Server linked server queries (MSSQL-to-MSSQL chaining), used where Linux targets connected to Windows database infrastructure |

---

## Proxy and Tunneling Tools

| Tool | Description |
|------|-------------|
| revsocks | Open-source reverse SOCKS proxy for Linux |
| pysoxy | Python-based SOCKS5 proxy server |
| GSocket | Global Socket toolkit for NAT-traversing covert channels |

---

## AI Attribution Assessment

Scripts deployed during this campaign contained embedded step-by-step reasoning annotations consistent with output from large language model code generation tools. Unit 42 assesses this as a **possible** indicator of AI-assisted code development rather than evidence of an autonomous AI agent conducting the intrusion. The distinction is significant: AI-assisted scripting lowers the technical bar for producing functional offensive tooling, but does not imply the AI itself made targeting or operational decisions.

---

## MITRE ATT&CK TTPs

| Technique ID | Technique | Notes |
|-------------|-----------|-------|
| T1505.003 | Server Software Component: Web Shell | PHP webshells via `auto_prepend_file` hijacking |
| T1546.004 | Event Triggered Execution: Unix Shell Configuration Modification | `.bashrc` hijacking for credential capture |
| T1556.007 | Modify Authentication Process: Hybrid Identity | PHP login page modification for credential theft |
| T1071.001 | Application Layer Protocol: Web Protocols | SysGoRAT C2 communication |
| T1021.004 | Remote Services: SSH | SSH double-hop lateral movement |
| T1021.001 | Remote Services: Remote Desktop Protocol / Windows Remote Management | MSSQL double-hop lateral movement |
| T1572 | Protocol Tunneling | revsocks, pysoxy, GSocket covert tunnel tools |
| T1090.001 | Proxy: Internal Proxy | revsocks / pysoxy SOCKS5 proxy infrastructure |

---

## Lockheed Martin Kill Chain

| Phase | Activity |
|-------|----------|
| Exploitation | Initial access to Linux servers via unknown vector |
| Installation | SysGoRAT deployment; `auto_prepend_file` webshell persistence; `.bashrc` hijacking |
| C2 | revsocks / GSocket covert C2 channels |
| Actions on Objectives | Credential theft; lateral movement via SSH and MSSQL double-hops |

---

## Detection Opportunities

### `auto_prepend_file` Abuse

Monitor for modifications to PHP configuration files that add `auto_prepend_file` directives:
- `php.ini` changes adding `auto_prepend_file`
- `.user.ini` files created in web-accessible directories
- `.htaccess` files with `php_value auto_prepend_file` directives

### SysGoRAT (Go Backdoor)

- Hunt for unexpected Go runtime binaries on Linux government servers
- Monitor for outbound connections from web service accounts (e.g., `www-data`, `apache`, `nginx`)
- Look for ELF binaries compiled with Go toolchain in web root or `/tmp/`

### Proxy Tool Indicators

- `revsocks`, `pysoxy`, `gsocket` processes on Linux servers
- Outbound persistent connections from web servers to external IPs on non-standard ports

### Credential Theft Patterns

- `.bashrc` or `.bash_profile` modification by web service account users
- PHP source file writes by web service accounts to login page paths

---

## References

- [Unit 42 — AI-Powered Campaign Targets Linux Infrastructure (2026-10-15)](https://unit42.paloaltonetworks.com/ai-campaign-targets-linux-infrastructure/)
- [MITRE ATT&CK — T1505.003: Web Shell](https://attack.mitre.org/techniques/T1505/003/)
- [MITRE ATT&CK — T1546.004: Unix Shell Configuration Modification](https://attack.mitre.org/techniques/T1546/004/)
- [PHP Documentation — auto_prepend_file](https://www.php.net/manual/en/ini.core.php#ini.auto-prepend-file)
