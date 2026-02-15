# Suspicious TGT Request - Metasploit TicketOptions Fingerprint

## Description

Metasploit's Kerberos client module (`Msf::Exploit::Remote::Kerberos::Client::AsRequest`) produces TGT requests with TicketOptions value `0x50800000`, representing flags Forwardable, Proxiable, and Renewable. The Proxiable flag (bit 3) combined with the absence of Canonicalize (bit 15) is extremely rare in legitimate Windows environments and is a strong indicator of Metasploit usage.

False positive sources: Extremely rare. The Proxiable flag is almost never set by legitimate Windows clients. Tuning: verify that no legacy systems in your environment produce this TicketOptions value.

## MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| Tactic | Credential Access |
| Tactic ID | TA0006 |
| Technique | Steal or Forge Kerberos Tickets |
| Technique ID | T1558 |

## Lockheed Martin Kill Chain

| Phase |
|-------|
| Actions on Objectives |

## Splunk Detection Query

```spl
`wineventlog_security` EventCode=4768 Status=0x0
    Ticket_Options=0x50800000
| eval tool_fingerprint="Metasploit (Forwardable+Proxiable+Renewable, missing Canonicalize)"
| eval risk_score=90
| stats count min(_time) as firstTime max(_time) as lastTime
    values(Ticket_Encryption_Type) as encryption_types
    by Account_Name Client_Address Service_Name Ticket_Options tool_fingerprint risk_score
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| table firstTime lastTime Account_Name Client_Address Service_Name Ticket_Options tool_fingerprint encryption_types count risk_score
```

## Risk Score Logic

| Condition | Score | Rationale |
|-----------|-------|-----------|
| TicketOptions `0x50800000` | 90 | Metasploit-specific fingerprint with rare Proxiable flag - near-certain tool usage |

## Associated Threat Actors

| Actor | References |
|-------|-----------|
| Any adversary using Metasploit | [Metasploit Framework](https://www.metasploit.com/) |

## References

- [NVISO - Hunting Kerberos: Decode TGT TicketOptions with KQL](https://blog.nviso.eu/2026/02/12/capture-the-kerberos-flag-detecting-kerberos-anomalies/)
- [MITRE ATT&CK - Steal or Forge Kerberos Tickets (T1558)](https://attack.mitre.org/techniques/T1558/)
