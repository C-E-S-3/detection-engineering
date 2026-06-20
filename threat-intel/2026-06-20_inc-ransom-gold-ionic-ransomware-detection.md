---
scraped_at: 2026-06-20T00:00:00Z
source_url: https://attack.mitre.org/groups/G1032/
report_type: threat-intel
severity: high
title: "INC Ransom (GOLD IONIC / G1032): Major RaaS Surge 2026 — 830+ Victims, Detection Coverage"
---

## Summary

INC Ransom (tracked by MITRE as G1032, by Secureworks as GOLD IONIC) is a Ransomware-as-a-Service operation active since July 2023. In 2026 it has seen significant growth following the disruption of LockBit and the shutdown of BlackCat/ALPHV, with affiliates migrating to INC. Over 830 confirmed victims across industrial, healthcare, and education sectors.

## Key IOCs

| Indicator | Type | Notes |
|-----------|------|-------|
| `.INC` | File extension | Encrypted file extension appended by ransomware |
| `INC-README.txt` | Ransom note | Dropped in each affected directory |
| `INC-README.html` | Ransom note | Alternate ransom note format |
| `INC_Update` | Scheduled task | Persistence mechanism name |
| `inc-decrypt.onion` | C2/payment | Victim communication / payment portal |
| `--file`, `--dir`, `--ens`, `--lhd`, `--sup`, `--debug` | CLI flags | INC encryptor command-line arguments |

## TTPs (MITRE ATT&CK)

| Tactic | Technique ID | Description |
|--------|-------------|-------------|
| Initial Access | T1190 | FortiGate CVE-2024-55591 / CVE-2024-23113 exploitation |
| Initial Access | T1566 | Spear-phishing email delivery |
| Execution | T1059 | Command and scripting interpreter |
| Persistence | T1053.005 | Scheduled task (INC_Update) |
| Persistence | T1078 | Valid accounts (stolen credentials) |
| Privilege Escalation | T1068 | Exploitation for privilege escalation |
| Defense Evasion | T1027 | Obfuscated files or information |
| Credential Access | T1003 | Credential dumping (Mimikatz, LSASS) |
| Discovery | T1016 | System network configuration discovery |
| Discovery | T1018 | Remote system discovery |
| Lateral Movement | T1021.001 | RDP |
| Lateral Movement | T1021 | PsExec, WMI |
| Collection | T1074 | Data staged (password-protected archives) |
| Exfiltration | T1041 | Exfiltration over C2 channel |
| Impact | T1486 | Data encrypted for impact |
| Impact | T1490 | Inhibit system recovery (shadow copy deletion) |

## Detection Rules

Wazuh rules 103300–103380 in `inc_ransomware.xml` provide coverage for:
- File encryption (.INC extension, ransom notes): 103300–103302
- Encryptor process CLI flags: 103310–103311
- Shadow copy/backup deletion: 103320–103321
- PsExec lateral movement: 103330–103331
- Data staging (archive creation): 103340
- C2 onion domain: 103350
- Credential dumping: 103360
- FortiGate initial access: 103370
- Multi-signal correlation: 103380

## Mitigation

1. Patch FortiGate: CVE-2024-55591 and CVE-2024-23113 are known INC entry points
2. Enable MFA on all VPN/RDP access
3. Restrict PsExec and WMI administrative access
4. Offline backup strategy to survive shadow copy deletion
5. Behavioral EDR monitoring for mass file modification patterns
