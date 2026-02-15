# TGT Request Missing Canonicalize Flag - Bitwise Analysis

## Description

Rather than relying on static hex values that attackers can modify, this detection uses bitwise analysis to identify any TGT request where the Canonicalize flag (bit 15) is absent. This catches both known tool signatures and novel TicketOptions values. The approach uses Splunk's `tonumber()` to convert the hex TicketOptions and a modulo/division-based bit check to test bit 15. In MSB-0 numbering, bit 15 corresponds to `0x00010000` (decimal 65536). Legitimate Windows clients always set the Canonicalize flag, making its absence a high-fidelity detection signal for offensive tooling including Rubeus, Impacket, Certipy, and Whisker.

False positive sources: Non-Windows Kerberos clients (some Linux/Unix implementations, older Java-based Kerberos libraries). Tuning: exclude known non-Windows client IPs after baselining.

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
| eval ticket_opts_dec=tonumber(replace(Ticket_Options, "^0x", ""), 16)
| eval canonicalize_set=if((floor(ticket_opts_dec / 65536) % 2) == 1, 1, 0)
| eval forwardable_set=if((floor(ticket_opts_dec / 1073741824) % 2) == 1, 1, 0)
| eval proxiable_set=if((floor(ticket_opts_dec / 268435456) % 2) == 1, 1, 0)
| eval renewable_set=if((floor(ticket_opts_dec / 8388608) % 2) == 1, 1, 0)
| eval renewable_ok_set=if((floor(ticket_opts_dec / 16) % 2) == 1, 1, 0)
| where canonicalize_set=0 AND forwardable_set=1
| eval flag_summary=mvappend(
    if(forwardable_set=1, "Forwardable", null()),
    if(proxiable_set=1, "Proxiable", null()),
    if(renewable_set=1, "Renewable", null()),
    if(renewable_ok_set=1, "Renewable-ok", null()),
    "MISSING: Canonicalize")
| eval risk_score=case(
    proxiable_set=1, 90,
    renewable_set=1 AND renewable_ok_set=0, 85,
    1=1, 80)
| stats count min(_time) as firstTime max(_time) as lastTime
    values(flag_summary) as flag_summary values(Ticket_Encryption_Type) as encryption_types
    by Account_Name Client_Address Service_Name Ticket_Options risk_score
| where Account_Name!="*$"
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| sort - risk_score
| table firstTime lastTime Account_Name Client_Address Service_Name Ticket_Options flag_summary encryption_types count risk_score
```

## Risk Score Logic

| Condition | Score | Rationale |
|-----------|-------|-----------|
| Missing Canonicalize + Proxiable set | 90 | Metasploit fingerprint - Proxiable is extremely rare in legitimate requests |
| Missing Canonicalize + Renewable without Renewable-ok | 85 | Rubeus kerberoast variant - unusual flag combination |
| Missing Canonicalize (general) | 80 | Generic offensive tool indicator - all major tools omit this flag |

## Associated Threat Actors

| Actor | References |
|-------|-----------|
| Any adversary using Rubeus | [GhostPack - Rubeus](https://github.com/GhostPack/Rubeus) |
| Any adversary using Impacket | [Impacket](https://github.com/fortra/impacket) |
| Any adversary using Certipy | [Certipy - ADCS exploitation](https://github.com/ly4k/Certipy) |
| Any adversary using Metasploit | [Metasploit Framework](https://www.metasploit.com/) |

## References

- [NVISO - Hunting Kerberos: Decode TGT TicketOptions with KQL](https://blog.nviso.eu/2026/02/12/capture-the-kerberos-flag-detecting-kerberos-anomalies/)
- [MITRE ATT&CK - Steal or Forge Kerberos Tickets (T1558)](https://attack.mitre.org/techniques/T1558/)
