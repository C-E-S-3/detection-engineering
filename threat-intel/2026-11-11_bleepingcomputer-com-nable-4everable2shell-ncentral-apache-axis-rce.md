---
scraped_at: 2026-11-13T00:00:00Z
source_url: https://www.bleepingcomputer.com/news/security/new-n-able-4everable2shell-zero-day-exploited-hours-after-poc-released/
report_type: threat-intel
severity: high
title: "N-able N-central 4EverAble2Shell: Apache Axis CVE-2026-90436 Exploited for XMRig Miner Deployment"
---

# N-able N-central 4EverAble2Shell: Apache Axis CVE-2026-90436 Exploited for XMRig Miner Deployment

**Source:** BleepingComputer / Huntress / WatchTowr  
**Published:** 2026-11-11  
**Severity:** High  

## Summary

A zero-day vulnerability chain dubbed "4EverAble2Shell" in N-able N-central RMM (Remote Monitoring and Management) software was exploited in the wild within hours of a proof-of-concept being published. The chain combines an Apache Axis flaw (CVE-2026-90436) with a separate N-central privilege escalation weakness to achieve unauthenticated root-level code execution on N-central servers.

Huntress confirmed at least 21 affected systems including servers running the latest security patch (N-central 2026.4 HF2 / build 2026.4.1.26). The post-compromise payload observed was an XMRig Monero cryptocurrency miner delivered via a shell script. WatchTowr reported active probing for the vulnerability immediately after PoC publication.

The chain requires the N-central Legacy API to be enabled, which is a non-default configuration. N-able has restricted the Legacy API and Intune integration features as an emergency mitigation.

## Technical Details

**Attack Chain:**
1. Attacker sends unauthenticated request to Legacy API endpoint in N-central
2. Apache Axis (CVE-2026-90436) enables command injection through the SOAP/HTTP handler
3. N-central privilege escalation weakness elevates to root
4. Post-compromise: downloads shell script installing XMRig Monero miner

**Prerequisite:** Legacy API functionality must be enabled (non-default). N-central servers with Legacy API disabled are not exposed to this specific chain (per Huntress).

**Forensic artifacts:** Unexpected script backup files and suspicious symbolic links involving `flag_default.json` observed on compromised systems. Normal N-central support activity can produce similar process activity — context matters.

**Additional chain:** A separate "Agent2Shell" technique allows SYSTEM-level command execution on managed Windows agents, also tied to this research.

## Indicators of Compromise

### IP Addresses

| Indicator | Context |
|-----------|---------|
| `157.20.241[.]16` | Active exploitation source IP — observed attacking N-central servers after PoC publication (WatchTowr) |

### Hashes

None confirmed from available sources.

### Domains

None confirmed from available sources.

## MITRE ATT&CK Mapping

| Tactic | ID | Technique |
|--------|-----|-----------|
| Execution | TA0002 | T1190 — Exploit Public-Facing Application |
| Privilege Escalation | TA0004 | T1068 — Exploitation for Privilege Escalation |
| Impact | TA0040 | T1496 — Resource Hijacking (XMRig miner) |

## Associated Threat Actors

Opportunistic financially motivated actors; no attribution to a named group as of this report.

## References

- [BleepingComputer — New N-able "4EverAble2Shell" zero-day exploited hours after PoC released](https://www.bleepingcomputer.com/news/security/new-n-able-4everable2shell-zero-day-exploited-hours-after-poc-released/)
- [SecurityWeek — Hackers Exploit New N-central Zero-Day Hours After PoC Publication](https://www.securityweek.com/hackers-exploit-new-n-central-zero-day-hours-after-poc-publication/)
- [The Hacker News — New N-central Exploits Work Against Patched Servers, Enable Root RCE](https://thehackernews.com/2026/11/new-n-central-exploits-work-against.html)
- [CybersecurityNews — N-able N-central Zero-Day Exploits Target Patched Servers](https://cybersecuritynews.com/n-able-n-central-zero-day-exploits/)
