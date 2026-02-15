# Kerberos Encryption Downgrade - DES Encryption in Ticket Requests

## Description

DES encryption types (`0x03` DES-CBC-MD5 and `0x01` DES-CBC-CRC) are deprecated and disabled by default in modern Windows environments. Any Kerberos ticket request (TGT or TGS) using DES encryption is almost certainly the result of a misconfigured legacy system or an attacker using outdated tooling to forge tickets. This detection has very few false positives in environments where DES is properly disabled via Group Policy.

False positive sources: Extremely rare. Only legacy systems that explicitly require DES encryption (e.g., very old Unix/Linux Kerberos clients, some legacy NAS appliances). Tuning: if DES is disabled in your environment via Group Policy, any match is immediately high priority.

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
`wineventlog_security` (EventCode=4768 OR EventCode=4769)
    (Ticket_Encryption_Type=0x03 OR Ticket_Encryption_Type=0x01)
| eval event_type=case(
    EventCode=4768, "TGT Request",
    EventCode=4769, "TGS Request",
    1=1, "Unknown")
| eval encryption_name=case(
    Ticket_Encryption_Type="0x03", "DES-CBC-MD5 (DEPRECATED)",
    Ticket_Encryption_Type="0x01", "DES-CBC-CRC (DEPRECATED)",
    1=1, "Unknown DES variant")
| eval risk_score=95
| stats count min(_time) as firstTime max(_time) as lastTime
    values(event_type) as event_types values(Ticket_Options) as ticket_options
    by Account_Name Client_Address Service_Name Ticket_Encryption_Type encryption_name risk_score
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| table firstTime lastTime Account_Name Client_Address Service_Name event_types Ticket_Encryption_Type encryption_name ticket_options count risk_score
```

## Risk Score Logic

| Condition | Score | Rationale |
|-----------|-------|-----------|
| Any DES encryption in Kerberos requests | 95 | Deprecated encryption - almost certainly forged ticket or severely misconfigured legacy system |

## Associated Threat Actors

| Actor | References |
|-------|-----------|
| Any adversary using Mimikatz (Golden/Silver Ticket) | [Mimikatz](https://github.com/gentilkiwi/mimikatz) |
| Any adversary using Impacket (ticketer.py) | [Impacket](https://github.com/fortra/impacket) |

## References

- [MITRE ATT&CK - Steal or Forge Kerberos Tickets (T1558)](https://attack.mitre.org/techniques/T1558/)
- [Microsoft - Event 4768 Documentation](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4768)
- [Microsoft - Event 4769 Documentation](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4769)
