# Kerberoasting - TGS Request with RC4 Encryption

## Description

Kerberoasting attacks request Kerberos service tickets (TGS) for accounts with Service Principal Names (SPNs) and specifically request RC4 encryption (`0x17`) because it is significantly faster to crack offline than AES. This detection monitors Event ID 4769 for TGS requests using RC4 encryption targeting non-machine service accounts, with TicketOptions values commonly observed in Kerberoasting tools. The risk score is elevated when multiple unique services are targeted, indicating automated SPN enumeration.

False positive sources: Legacy applications that require RC4 encryption, service accounts on older systems. Tuning: exclude known legacy service accounts that legitimately use RC4, and filter machine accounts (ending in `$`).

## MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| Tactic | Credential Access |
| Tactic ID | TA0006 |
| Technique | Steal or Forge Kerberos Tickets: Kerberoasting |
| Technique ID | T1558.003 |

## Lockheed Martin Kill Chain

| Phase |
|-------|
| Actions on Objectives |

## Splunk Detection Query

```spl
`wineventlog_security` EventCode=4769
    Ticket_Encryption_Type=0x17
    (Ticket_Options=0x40810000 OR Ticket_Options=0x40800000 OR Ticket_Options=0x40810010
     OR Ticket_Options=0x40800010 OR Ticket_Options=0x50800000)
| where Service_Name!="*$" AND Service_Name!="krbtgt"
| eval tool_indicator=case(
    Ticket_Options="0x40800000", "Rubeus kerberoast default",
    Ticket_Options="0x40800010", "Rubeus/Impacket (missing Canonicalize)",
    Ticket_Options="0x50800000", "Metasploit (Forwardable+Proxiable+Renewable)",
    Ticket_Options="0x40810000", "Impacket GetUserSPNs (modified) or legitimate",
    Ticket_Options="0x40810010", "Impacket GetUserSPNs default or legitimate",
    1=1, "Unknown")
| eval risk_score=case(
    Ticket_Options="0x40800000" OR Ticket_Options="0x40800010", 90,
    Ticket_Options="0x50800000", 95,
    Ticket_Options="0x40810000" OR Ticket_Options="0x40810010", 70,
    1=1, 65)
| stats count min(_time) as firstTime max(_time) as lastTime dc(Service_Name) as unique_services
    values(Service_Name) as targeted_services values(tool_indicator) as tool_indicator
    by Account_Name Client_Address Ticket_Options Ticket_Encryption_Type risk_score
| eval risk_score=if(unique_services > 5, min(risk_score + 15, 100), risk_score)
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| sort - risk_score
| table firstTime lastTime Account_Name Client_Address Ticket_Options Ticket_Encryption_Type tool_indicator targeted_services unique_services count risk_score
```

## Risk Score Logic

| Condition | Score | Rationale |
|-----------|-------|-----------|
| Metasploit TicketOptions (`0x50800000`) | 95 | Metasploit fingerprint with rare Proxiable flag |
| Rubeus/Impacket TicketOptions (missing Canonicalize) | 90 | High-confidence tool fingerprint |
| Impacket/legitimate TicketOptions (with Canonicalize) | 70 | RC4 is suspicious but TicketOptions could be legitimate |
| More than 5 unique services targeted | +15 | Volume indicates automated SPN enumeration |

## Associated Threat Actors

| Actor | References |
|-------|-----------|
| Any adversary using Rubeus | [GhostPack - Rubeus](https://github.com/GhostPack/Rubeus) |
| Any adversary using Impacket | [Impacket - GetUserSPNs.py](https://github.com/fortra/impacket) |
| Any adversary using Metasploit | [Metasploit Framework](https://www.metasploit.com/) |

## References

- [Splunk - Detecting Active Directory Kerberos Attacks](https://www.splunk.com/en_us/blog/security/detecting-active-directory-kerberos-attacks-threat-research-release-march-2022.html)
- [Splunk Security Content - Kerberoasting SPN Request with RC4](https://research.splunk.com/endpoint/5cc67381-44fa-4111-8a37-7a230943f027/)
- [MITRE ATT&CK - Kerberoasting (T1558.003)](https://attack.mitre.org/techniques/T1558/003/)
- [ADSecurity - Detecting Kerberoasting Activity](https://adsecurity.org/?p=3458)
