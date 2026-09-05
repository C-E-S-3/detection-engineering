---
title: "Spring Ring: Voice Phishing via Microsoft Teams Leads to PetitPotam NTLM Relay"
source: Unit 42 (Palo Alto Networks)
date: 2026-09-05
tags: [vishing, teams, ntlm-relay, petitpotam, rmm-abuse, initial-access]
mitre_tactics: [TA0001, TA0008, TA0011]
---

# Spring Ring: Voice Phishing via Microsoft Teams Leads to PetitPotam NTLM Relay

## Summary

Unit 42 documented an ongoing social engineering campaign they track as **Spring Ring**, active January–April 2026, targeting enterprise employees via unsolicited Microsoft Teams calls originating from attacker-controlled external tenants. After establishing trust through impersonation of IT support personnel, attackers convince victims to install a remote monitoring and management (RMM) tool, then use PetitPotam to coerce NTLM authentication from victim machines to attacker-controlled relay servers.

## Campaign Details

Attackers register attacker-controlled Microsoft Entra tenants with display names designed to impersonate internal IT departments (examples: "ITProtectionDepartment", "MandatoryNetworkMonitoring"). Because these are legitimate Microsoft-hosted `*.onmicrosoft.com` tenants, they display a verified Teams identity rather than triggering standard phishing filters.

The attack chain:
1. **Initial contact**: Unsolicited Teams call from external tenant impersonating IT helpdesk
2. **Pretext**: Victim told their workstation has a security alert requiring immediate remediation
3. **RMM installation**: Victim instructed to allow screen share or install an RMM agent
4. **Payload delivery**: Attacker uses RMM access to execute a PowerShell-based RAT hosted at `san-sid[.]com`
5. **NTLM relay**: Attacker triggers PetitPotam (MS-EFSRPC `EfsRpcOpenFileRaw` call) from victim machine to attacker-controlled listener, capturing machine account NTLM hashes
6. **Relay to AD CS**: Captured NTLM credentials relayed to an Active Directory Certificate Services (AD CS) enrollment endpoint to obtain a machine certificate, enabling persistent domain authentication

Unit 42 identified 26 distinct attacker identities operating this campaign.

## IOCs

### Domains

| Indicator | Role |
|-----------|------|
| `san-sid[.]com` | PowerShell RAT payload delivery host |

### IP Addresses

| Indicator | Role |
|-----------|------|
| `193.32.248[.]251` | Attacker proxy/VPN infrastructure |
| `185.65.134[.]209` | Attacker proxy/VPN infrastructure |

### File Hashes

| Hash | Type | Description |
|------|------|-------------|
| `24ab9fe5d5be62d3bf055a0ca4508e8bca2996b6d78649dce8145d8a27bc1c5b` | SHA256 | Obfuscated PowerShell RAT payload retrieved from `san-sid[.]com` |

## MITRE ATT&CK Mapping

| Technique | ID | Description |
|-----------|----|-------------|
| Phishing: Spear-phishing via Service | T1566.004 | Teams vishing via external tenant impersonation |
| Remote Access Software | T1219 | RMM tool installed by victim under social engineering |
| Forced Authentication | T1187 | PetitPotam MS-EFSRPC call to coerce NTLM hash |
| Adversary-in-the-Middle: LLMNR/NBT-NS Poisoning and SMB Relay | T1557.001 | NTLM relay to AD CS endpoint |
| Valid Accounts | T1078 | Machine certificate used for persistent domain auth |

## Detection Opportunities

- **Teams external tenant messages**: Block or alert on inbound Teams calls/messages from external tenants not on an approved list (Entra ID admin settings)
- **RMM execution preceded by Teams session**: Endpoint process creation of RMM binaries correlated with recent Teams activity
- **MS-EFSRPC outbound calls**: Unexpected outbound SMB (445) from endpoints to external IPs, particularly following RMM tool execution
- **AD CS unusual enrollment**: Machine certificate enrollment from non-domain-joined or newly-joined endpoints

## References

- [Unit 42: Spring Ring Voice Phishing Campaigns](https://unit42.paloaltonetworks.com/spring-ring-voice-phishing-campaigns/)
- [GBHackers: Spring Ring Campaign](https://gbhackers.com/spring-ring-campaign/)
- [Help Net Security: Spring Ring Vishing Campaign via Microsoft Teams](https://www.helpnetsecurity.com/2026/09/01/spring-ring-vishing-campaign-microsoft-teams/)
- [MITRE ATT&CK T1566.004](https://attack.mitre.org/techniques/T1566/004/)
- [MITRE ATT&CK T1557.001](https://attack.mitre.org/techniques/T1557/001/)
- [PetitPotam MS-EFSRPC Forced Authentication (CERT-FR)](https://www.cert.ssi.gouv.fr/actualite/CERTFR-2021-ACT-035/)
