# Kerberos Anomaly Baseline - Rare TicketOptions Discovery

## Description

This is a hunting query rather than an alerting rule. It identifies TicketOptions values that deviate from the environment baseline by finding rare hex values across all TGT requests. This helps discover novel tool signatures, misconfigured systems, or attacker customization that evades static-value detections. Run periodically and investigate any new or rare TicketOptions values that appear. Values representing less than 1% of total TGT requests are surfaced with decoded flag analysis.

False positive sources: Legitimate non-Windows Kerberos clients, newly deployed systems, or configuration changes may introduce new TicketOptions values. Tuning: maintain a baseline of known-good rare values and focus on newly appearing entries.

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
| stats count dc(Account_Name) as unique_accounts values(Account_Name) as sample_accounts
    values(Client_Address) as source_ips values(Ticket_Encryption_Type) as encryption_types
    by Ticket_Options
| eventstats sum(count) as total_requests
| eval pct_of_total=round((count / total_requests) * 100, 4)
| where pct_of_total < 1.0
| eval ticket_opts_dec=tonumber(replace(Ticket_Options, "^0x", ""), 16)
| eval canonicalize_set=if((floor(ticket_opts_dec / 65536) % 2) == 1, "Yes", "No")
| eval forwardable_set=if((floor(ticket_opts_dec / 1073741824) % 2) == 1, "Yes", "No")
| eval proxiable_set=if((floor(ticket_opts_dec / 268435456) % 2) == 1, "Yes", "No")
| eval renewable_set=if((floor(ticket_opts_dec / 8388608) % 2) == 1, "Yes", "No")
| sort pct_of_total
| table Ticket_Options count pct_of_total unique_accounts forwardable_set proxiable_set renewable_set canonicalize_set encryption_types sample_accounts source_ips
```

## Risk Score Logic

| Condition | Score | Rationale |
|-----------|-------|-----------|
| Hunting query - no automated risk scoring | N/A | Results require manual analyst review to determine if rare TicketOptions values represent malicious tools, misconfigured systems, or benign outliers |

## Associated Threat Actors

| Actor | References |
|-------|-----------|
| Any adversary using custom or modified Kerberos tools | [NVISO - Hunting Kerberos](https://blog.nviso.eu/2026/02/12/capture-the-kerberos-flag-detecting-kerberos-anomalies/) |

## References

- [NVISO - Hunting Kerberos: Decode TGT TicketOptions with KQL](https://blog.nviso.eu/2026/02/12/capture-the-kerberos-flag-detecting-kerberos-anomalies/)
- [MITRE ATT&CK - Steal or Forge Kerberos Tickets (T1558)](https://attack.mitre.org/techniques/T1558/)
- [TrustedSec - The Art of Bypassing Kerberoast Detections with Orpheus](https://trustedsec.com/blog/the-art-of-bypassing-kerberoast-detections-with-orpheus)
