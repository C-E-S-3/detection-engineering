# Suspicious TGT Request - Offensive Tool TicketOptions Fingerprint

## Description

Offensive tools such as Rubeus, Impacket, Certipy, and Whisker produce TGT requests with hardcoded TicketOptions values that are missing the Canonicalize flag (bit 15). The hex value `0x40800010` (Forwardable, Renewable, Renewable-ok) is the default for Rubeus and several Impacket modules. Legitimate Windows TGT requests almost always include the Canonicalize flag, making its absence a high-fidelity indicator of tool usage. This detection targets Event ID 4768 (TGT request) on Domain Controllers.

False positive sources: Very rare. Some non-Windows Kerberos clients (e.g., older Linux/Unix implementations) may produce non-standard TicketOptions. Tuning: baseline TicketOptions values in your environment for 7-14 days before alerting.

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
    (Ticket_Options=0x40800010 OR Ticket_Options=0x40800000 OR Ticket_Options=0x40800018)
| eval tool_fingerprint=case(
    Ticket_Options="0x40800010", "Rubeus/Impacket/Certipy/Whisker (Forwardable+Renewable+Renewable-ok, missing Canonicalize)",
    Ticket_Options="0x40800000", "Rubeus Kerberoast (Forwardable+Renewable, missing Canonicalize+Renewable-ok)",
    Ticket_Options="0x40800018", "Rubeus variant (Forwardable+Renewable+Enc-tkt-in-skey+Renewable-ok)",
    1=1, "Unknown suspicious TicketOptions")
| eval risk_score=case(
    Ticket_Options="0x40800010", 85,
    Ticket_Options="0x40800000", 80,
    Ticket_Options="0x40800018", 80,
    1=1, 70)
| stats count min(_time) as firstTime max(_time) as lastTime values(tool_fingerprint) as tool_fingerprint
    values(Ticket_Encryption_Type) as encryption_types
    by Account_Name Client_Address Service_Name Ticket_Options risk_score
| where Account_Name!="*$"
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| sort - risk_score
| table firstTime lastTime Account_Name Client_Address Service_Name Ticket_Options tool_fingerprint encryption_types count risk_score
```

## Risk Score Logic

| Condition | Score | Rationale |
|-----------|-------|-----------|
| TicketOptions `0x40800010` | 85 | Default Rubeus/Impacket/Certipy/Whisker fingerprint - high confidence |
| TicketOptions `0x40800000` | 80 | Rubeus kerberoast default - missing Canonicalize and Renewable-ok |
| TicketOptions `0x40800018` | 80 | Rubeus variant with Enc-tkt-in-skey flag |
| Other suspicious TicketOptions | 70 | Unknown tool or modified configuration |

## Associated Threat Actors

| Actor | References |
|-------|-----------|
| Any adversary using Rubeus | [GhostPack - Rubeus](https://github.com/GhostPack/Rubeus) |
| Any adversary using Impacket | [Impacket](https://github.com/fortra/impacket) |
| Any adversary using Certipy | [Certipy - ADCS exploitation](https://github.com/ly4k/Certipy) |

## References

- [NVISO - Hunting Kerberos: Decode TGT TicketOptions with KQL](https://blog.nviso.eu/2026/02/12/capture-the-kerberos-flag-detecting-kerberos-anomalies/)
- [MITRE ATT&CK - Steal or Forge Kerberos Tickets (T1558)](https://attack.mitre.org/techniques/T1558/)
