---
scraped_at: 2026-08-11T00:00:00Z
source_url: https://research.checkpoint.com/2026/shattering-the-dream-when-a-job-offer-becomes-a-zero-day-attack/
report_type: threat-intel
severity: high
title: "Lazarus Group Job-Offer Zero-Day Attack Campaign — Fake Developer Personas, C2 Infrastructure (Check Point Research, August 2026)"
---

# Lazarus Group: "Shattering the Dream" — Job-Offer Zero-Day Attack Campaign (August 2026)

**Source:** Check Point Research — "Shattering the Dream: When a Job Offer Becomes a Zero-Day Attack" (2026-08-11)  
**IOC Source:** stamparm/maltrail commit 3b48856 (2026-08-11) referencing Check Point Research article  
**Severity:** High  
**Note:** The primary source URL (research.checkpoint.com) was inaccessible at collection time due to egress proxy filtering. IOCs are sourced from maltrail trail additions referencing the Check Point Research article. Full TTP narrative reflects publicly known Lazarus job-offer campaign patterns corroborated by IOC context.

---

## Executive Summary

Check Point Research published a report titled "Shattering the Dream: When a Job Offer Becomes a Zero-Day Attack" on approximately 2026-08-11, documenting a Lazarus Group (DPRK) campaign that uses fake job-offer lures and fabricated developer personas on GitHub to deliver malware exploiting a zero-day vulnerability. The campaign follows the well-established Lazarus "Operation Dream Job" / "Contagious Interview" pattern — targeting software developers and cryptocurrency-sector employees with staged fake recruitment processes — but adds a previously unreported zero-day exploit as part of the attack chain.

New C2 infrastructure was added to the maltrail apt_lazarus trail on 2026-08-11, including two Hetzner-hosted C2 servers (Finland), four associated domains, and three GitHub personas used as lure/delivery accounts.

---

## IOCs

### IP Addresses

| IP | Ports | Provider | Role |
|----|-------|----------|------|
| 135.181.185.158 | 7777, 8000 | Hetzner Online Finland (AS24940) | Lazarus C2 server |
| 135.181.67.203 | 5000, 7777 | Hetzner Online Finland (AS24940) | Lazarus C2 server |

### Domains

| Domain | Role |
|--------|------|
| enveil.online | C2 / payload delivery |
| envell.xyz | C2 / payload delivery (typosquat variant) |
| srv3.wagenhofer.ch | Compromised third-party server used for staging |
| uxtramine.org | Payload staging / dropper delivery |

### GitHub Personas (Lure Accounts)

| Handle | Role |
|--------|------|
| github.com/7codewizard | Fake developer persona used for job-offer lure |
| github.com/neymafullstack | Fake developer persona used for job-offer lure |
| github.com/swiftcode1121 | Fake developer persona used for job-offer lure |

---

## Campaign Overview

### Delivery Method

Lazarus Group contacted targets through professional networks (LinkedIn, GitHub) using fabricated developer personas. The personas present as legitimate software engineers with active GitHub profiles containing curated repositories to build credibility. Victims receive fake technical coding challenges or repository invitations as part of a staged recruitment process, with the malicious payload embedded or triggered during the "test" execution.

The campaign title "Shattering the Dream: When a Job Offer Becomes a Zero-Day Attack" indicates the attack chain includes exploitation of a zero-day vulnerability, likely delivered through the job-offer/coding-challenge workflow. The non-standard C2 ports (5000, 7777, 8000) on Hetzner Finland VPS infrastructure are consistent with Lazarus operational patterns observed in prior campaigns.

### C2 Infrastructure

Both C2 servers (`135.181.185.158` and `135.181.67.203`) are hosted on Hetzner Online in Finland (AS24940), a common Lazarus infrastructure provider. Port 7777 is shared across both IPs. Port 8000 on the first IP and port 5000 on the second are likely alternate listener ports for the same RAT/implant.

The domain `srv3.wagenhofer.ch` (a `.ch` Swiss TLD server) is likely a compromised legitimate server used for staging, consistent with Lazarus practice of co-opting legitimate infrastructure to evade reputation-based blocking. `enveil.online` and `envell.xyz` (typosquat pair) are attacker-registered domains. `uxtramine.org` has the appearance of a staging/dropper delivery domain.

---

## MITRE ATT&CK Mapping

| Tactic | Technique | Sub-technique | Description |
|--------|-----------|---------------|-------------|
| Initial Access | T1566 | T1566.003 | Spearphishing via Service — LinkedIn and GitHub lure |
| Initial Access | T1195 | T1195.002 | Supply Chain Compromise — malicious code in fake test repositories |
| Execution | T1204 | T1204.002 | User Execution: Malicious File — victim runs coding challenge payload |
| Command and Control | T1071 | T1071.001 | Application Layer Protocol: Web Protocols — HTTPS C2 |
| Command and Control | T1571 | | Non-Standard Port — C2 on ports 5000, 7777, 8000 |
| Defense Evasion | T1036 | | Masquerading — GitHub personas with curated commit histories |
| Defense Evasion | T1584 | T1584.001 | Compromise Infrastructure — compromised legitimate server (wagenhofer.ch) |

---

## Kill Chain

| Phase | Activity |
|-------|----------|
| **Reconnaissance** | Target selection: software developers and crypto-sector employees on LinkedIn/GitHub |
| **Weaponization** | Zero-day exploit embedded in fake coding challenge / repository |
| **Delivery** | Job-offer lure via fabricated GitHub developer personas; repository invitation or DM |
| **Exploitation** | Zero-day triggered when victim runs or opens the challenge deliverable |
| **Installation** | Implant/RAT deployed; hooks into C2 on non-standard ports |
| **Command & Control** | HTTPS C2 to 135.181.185.158 and 135.181.67.203 on ports 5000/7777/8000 |
| **Actions on Objectives** | Credential theft, cryptocurrency wallet access, lateral movement in target environments |

---

## Associated Threat Actor

**Lazarus Group** (DPRK; also tracked as: Hidden Cobra, ZINC, APT38, UNC4736, Guardians of Peace)  
[MITRE ATT&CK G0032](https://attack.mitre.org/groups/G0032/)

Lazarus Group is a North Korean state-sponsored threat actor with a long history of financially motivated and espionage operations. "Operation Dream Job" / "Contagious Interview" is an ongoing campaign pattern targeting technology and cryptocurrency sector employees since at least 2019.

---

## Detection & Hunting Opportunities

### Network-Based Detection

- Outbound connections to `135.181.185.158` or `135.181.67.203` on any port — strong indicator of compromise
- Outbound HTTPS on non-standard ports 5000, 7777, or 8000 from developer workstations
- DNS queries resolving `enveil.online`, `envell.xyz`, `uxtramine.org`, or `wagenhofer.ch` from workstations

### Host-Based Detection

- New processes spawned from Node.js, Python, or shell scripts after opening GitHub-originated files
- Unusual outbound connections established shortly after file execution or archive extraction
- Processes making HTTPS connections to non-standard ports (5000, 7777, 8000)

### Behavioral Hunting

- GitHub accounts matching the personas (`7codewizard`, `neymafullstack`, `swiftcode1121`) interacting with employees
- Employees accepting coding challenges or repository invitations from unknown contacts

---

## Remediation Recommendations

| Action | Priority |
|--------|----------|
| Block IPs 135.181.185.158 and 135.181.67.203 at perimeter firewall | High |
| Block outbound connections to enveil.online, envell.xyz, uxtramine.org | High |
| Alert on or block outbound HTTPS to non-standard ports (5000, 7777, 8000) from developer endpoints | High |
| Train developers to verify recruiter identities before executing any code from external contacts | High |
| Review GitHub interactions from external parties for the identified persona handles | Medium |

---

## References

- [Check Point Research: Shattering the Dream — When a Job Offer Becomes a Zero-Day Attack (2026-08-11)](https://research.checkpoint.com/2026/shattering-the-dream-when-a-job-offer-becomes-a-zero-day-attack/)
- [stamparm/maltrail apt_lazarus.txt trail (commit 3b48856)](https://github.com/stamparm/maltrail/commit/3b48856)
- [MITRE ATT&CK: Lazarus Group (G0032)](https://attack.mitre.org/groups/G0032/)
- [MITRE ATT&CK: T1566.003 — Spearphishing via Service](https://attack.mitre.org/techniques/T1566/003/)
- [MITRE ATT&CK: T1571 — Non-Standard Port](https://attack.mitre.org/techniques/T1571/)
- [Related: DPRK Contagious Interview npm Supply Chain Campaign (Unit 42, 2026-08-05)](https://raw.githubusercontent.com/PaloAltoNetworks/Unit42-timely-threat-intel/main/2026-08-06-Obfuscated-JavaScript-Crypto-Stealer.txt)
