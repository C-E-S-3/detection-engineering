---
scraped_at: 2026-09-04T00:00:00Z
source_url: https://research.checkpoint.com/2026/gambling-goblin-apache-module-implants-brazil-government/
report_type: threat-intel
severity: medium
title: "Gambling Goblin: Chinese-Speaking Actors Plant Malicious Apache Modules on Brazilian Government Sites to Redirect Traffic to Gambling Pages"
---

# Gambling Goblin: Chinese-Speaking Actors Plant Malicious Apache Modules on Brazilian Government Sites

## Summary

Check Point Research published research on a campaign they call "Gambling Goblin" involving Chinese-speaking threat actors (linked by TTP overlap to Earth Berberoka, a group known for targeting online gambling) who are implanting malicious Apache shared-object modules (`mod_*.so` files) on Brazilian federal, state, and municipal government web servers. The implanted modules act as transparent reverse proxies, silently redirecting a portion of web traffic — particularly visits from mobile devices — to Chinese-language online gambling and sports betting pages. The campaign has been active since mid-2025 and has affected dozens of `.gov.br` domains. No data exfiltration or espionage motive is currently attributed; the goal appears to be generating gambling referral/affiliate revenue using government site credibility to bypass ad filters and attract Brazilian users.

## Threat Actor

| Field | Value |
|-------|-------|
| Name | Gambling Goblin (Check Point designation) |
| Overlapping Actor | Earth Berberoka (Trend Micro); Chinese-speaking gambling-focused threat cluster |
| Origin | China (PRC-affiliated; Chinese-language gambling platforms as beneficiaries) |
| Targets | Brazilian government web servers (federal, state, municipal `.gov.br`) |
| Motivation | Financial — gambling affiliate/referral revenue; use of government site reputation |
| Active Since | Mid-2025 |

## Technical Details

### Initial Access
- Actors exploit known Apache/web server vulnerabilities or use stolen server credentials to gain access to `.gov.br` hosted environments
- Specific initial access vector not confirmed in public reporting; consistent with opportunistic exploitation of internet-facing Apache servers

### Malicious Apache Module Implant

| Component | Details |
|-----------|---------|
| Type | Apache Dynamic Shared Object (DSO) — `.so` shared library |
| Placement | Apache module directory (e.g., `/usr/lib/apache2/modules/`, `/etc/httpd/modules/`) |
| Activation | `LoadModule` directive added to Apache configuration |
| Function | Hooks into Apache request processing pipeline as a reverse proxy handler |
| Traffic Selection | Targets mobile User-Agent strings (Android, iOS); passes desktop traffic normally |
| Redirect Destination | Chinese-language gambling/sports betting sites; uses HTTP 302 redirect or transparent proxy |
| Persistence | Survives Apache restarts; persists until manually removed |

### Affected Infrastructure
- Dozens of confirmed `.gov.br` domains across Brazilian federal agencies, state governments, and municipal sites
- Site categories: traffic/transit agencies, social services, municipal chambers, state secretariats
- No Brazilian federal military or intelligence sites confirmed affected

## IOCs

No specific module filenames, hashes, or attacker IP addresses confirmed in public reporting. Apache module files will have non-standard names attempting to blend with legitimate modules.

IOC CSV files not updated (no confirmed stable IOCs to track).

## Detection Guidance

### Apache Module Integrity

```spl
index=linux sourcetype=auditd syscall=open OR syscall=openat
  path="/usr/lib/apache2/modules/*" OR path="/etc/httpd/modules/*"
  NOT (exe="/usr/sbin/apache2" OR exe="/usr/sbin/httpd" OR exe="/usr/bin/apt-get" OR exe="/usr/bin/yum")
| stats count by host user exe path _time
| table _time host user exe path count
```

- Alert on new `.so` files written to Apache module directories by non-package-manager processes
- Monitor `LoadModule` directives in Apache configuration files for unfamiliar module names
- Alert on Apache configuration file modifications outside of authorized change windows

### Traffic Anomaly
- Monitor for HTTP 302 redirects from `.gov.br` sites to external gambling/betting domains in proxy/WAF logs
- Alert on Apache access log entries where `User-Agent` mobile strings receive significantly different responses than desktop strings from the same URL

### Web Server Process Behavior
- Alert on Apache worker processes opening outbound TCP connections to external IPs (unexpected for a legitimate government content server)
- Monitor for `curl`, `wget`, or other download utilities spawned as children of Apache worker processes

## MITRE ATT&CK

| Tactic | Technique | ID |
|--------|-----------|-----|
| Initial Access | Exploit Public-Facing Application | T1190 |
| Persistence | Server Software Component: Web Shell / Module | T1505.003 |
| Defense Evasion | Masquerading | T1036 |
| Command and Control | Application Layer Protocol: Web Protocols | T1071.001 |
| Impact | Traffic Signaling / Resource Hijacking | T1496 |

## Lockheed Martin Kill Chain

| Phase |
|-------|
| Exploitation |
| Installation |
| Actions on Objectives |

## References

- [Check Point Research — Gambling Goblin Apache Module Implants](https://research.checkpoint.com/2026/gambling-goblin-apache-module-implants-brazil-government/)
- [Trend Micro — Earth Berberoka](https://www.trendmicro.com/en_us/research/22/d/earth-berberoka-gamblingnation.html)
- [MITRE ATT&CK T1505.003 — Server Software Component: Web Shell](https://attack.mitre.org/techniques/T1505/003/)
- [MITRE ATT&CK T1190 — Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/)
