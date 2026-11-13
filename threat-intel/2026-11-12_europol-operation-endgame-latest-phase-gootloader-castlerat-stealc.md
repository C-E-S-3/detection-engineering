---
scraped_at: 2026-11-13T00:00:00Z
source_url: https://www.bleepingcomputer.com/news/security/police-dismantles-gootloader-castlerat-stealc-malware-infrastructure/
report_type: threat-intel
severity: high
title: "Operation Endgame (Nov 2026): Europol Dismantles Gootloader, CastleRAT, StealC — 235 Servers, 257 Domains, 6.4M Credentials Recovered"
---

# Operation Endgame (Nov 2026): Europol Dismantles Gootloader, CastleRAT, StealC Infrastructure

**Source:** Europol / BleepingComputer / Help Net Security  
**Published:** 2026-11-12  
**Severity:** High  

## Summary

Europol announced the latest phase of Operation Endgame targeting major malware infrastructure. Running from November 9–11, 2026, the operation seized 235 servers and 257 domains used by Gootloader, CastleRAT, and StealC, and recovered approximately 6.4 million sets of stolen credentials. Additionally, 681 Gootloader-compromised websites were cleaned as part of the operation.

This follows Operation Endgame Phase 2 (June 2026) which targeted SocGholish, Amadey, and StealC. Nine countries participated: Bulgaria, Canada, Denmark, Germany, Moldova, the Netherlands, Poland, the United Kingdom, and the United States.

## Infrastructure Dismantled

| Family | Servers Seized | Domains Seized | Notes |
|--------|---------------|----------------|-------|
| Gootloader | 14 | 218 | 681 compromised WordPress sites cleaned |
| CastleRAT | 120 | 39 | First documented 2025 |
| StealC | 102 | — | Continuing from Phase 2 (June 2026) |
| **Total** | **235** | **257** | |

## Malware Families

**Gootloader:** JavaScript-based loader distributed through SEO-poisoned search results, disguising malicious payloads as legal documents, software, and business templates. Provides initial foothold for ransomware, infostealer, or RAT deployment. Associated with the GootKit actor group.

**CastleRAT:** Remote access trojan first publicly documented in 2025. Provides persistent backdoor access, C2 communication, and lateral movement capability.

**StealC:** Information stealer targeting stored browser credentials, session cookies, cryptocurrency wallets, and application secrets. Delivers collected data via HTTP POST to operator-controlled panels.

## Operational Significance

Seized infrastructure is taken out of criminal operators' hands, disrupting active campaigns. However, existing infections on victim systems remain active unless remediated. The 6.4 million recovered credential records may be used by law enforcement for victim notification.

Existing detections for Gootloader (SEO poisoning stages, WordPress C2 patterns, PowerShell registry decode) and StealC (credential POST patterns) remain relevant for active infections not covered by takedown.

## Indicators of Compromise

No new network IOCs were published for the seized infrastructure; domains and servers are under law enforcement control. For prior-phase IOCs (Gootloader SEO domains, StealC C2 panels, Amadey C2 hosts), see existing entries in `iocs/domain.csv` and `iocs/hash.csv` from Operation Endgame Phase 2 (June 2026).

## MITRE ATT&CK Mapping

| Tactic | ID | Technique |
|--------|-----|-----------|
| Initial Access | TA0001 | T1189 — Drive-by Compromise (Gootloader SEO poisoning) |
| Execution | TA0002 | T1059.007 — JavaScript (Gootloader) |
| Credential Access | TA0006 | T1555 — Credentials from Password Stores (StealC) |
| Command and Control | TA0011 | T1102.002 — Bidirectional Communication via Web Services |

## Associated Threat Actors

| Actor | Description | References |
|-------|-------------|-----------|
| GootKit operators | Gootloader initial access broker; ransomware affiliate facilitator | [MITRE G0078](https://attack.mitre.org/groups/G0078/) |
| CastleRAT operators | Eastern European cybercriminal group; first active 2025 | [BleepingComputer coverage](https://www.bleepingcomputer.com/news/security/police-dismantles-gootloader-castlerat-stealc-malware-infrastructure/) |

## References

- [BleepingComputer — Police dismantles Gootloader, CastleRAT, StealC malware infrastructure](https://www.bleepingcomputer.com/news/security/police-dismantles-gootloader-castlerat-stealc-malware-infrastructure/)
- [Help Net Security — Operation Endgame malware takedown turns up over 6 million stolen logins](https://www.helpnetsecurity.com/2026/11/12/europol-operation-endgame-malware-takedown/)
- [GBHackers — Europol Dismantles Three Major Malware Networks, Seizes 235 Servers](https://gbhackers.com/europol-dismantles-three-major-malware-networks/)
- [Cyberinsider — Police recover 6.4 million stolen records in malware takedown](https://cyberinsider.com/operation-endgame-malware-takedown-stolen-data-credentials/)
