---
scraped_at: 2026-07-24T08:00:00Z
source_url: https://www.group-ib.com/resources/research-hub/hollowgraph-iranian-m365-calendar-c2/
report_type: threat-intel
severity: critical
title: "HOLLOWGRAPH: Iranian MOIS Cavern Manticore Uses M365 Calendar as Covert C2 Dead Drop"
---

# HOLLOWGRAPH — M365 Calendar Two-Way C2 Dead Drop (Cavern Manticore / Iranian MOIS)

**Source:** Group-IB  
**Published:** 2026-07-20 to 2026-07-22  
**Severity:** Critical  

## Summary

Group-IB published a comprehensive analysis of **HollowGraph**, a .NET DLL espionage implant attributed with high confidence to **Cavern Manticore**, an Iranian Ministry of Intelligence and Security (MOIS)-linked threat actor. HollowGraph uses a hijacked Microsoft 365 mailbox calendar as a fully bidirectional command-and-control dead drop, with no attacker-owned infrastructure visible on the network. All C2 traffic flows over the legitimate `graph.microsoft.com` API endpoint.

Group-IB confirmed at least **12 victims** with activity spanning June 3 to July 9, 2026. Targeted sectors were not fully disclosed; Group-IB noted low-confidence infrastructure overlap with the Lyceum threat cluster.

### C2 Mechanism

1. The operator compromises an Entra ID (Azure AD) account with access to the target organization's M365 mailbox.
2. The operator creates a calendar event dated **2050-05-13** in the target's calendar — a date so far in the future it will never appear in any normal calendar view.
3. Encrypted operator tasking (RSA + AES-256-GCM) is attached to this event as a file attachment.
4. HollowGraph authenticates to Graph API using the compromised credentials and polls for calendar events using the OData filter: `GET /me/events?$filter=start/dateTime ge '2050-01-01'`
5. Tasking is decrypted and executed. Results are written back to the same calendar event as a new attachment (exfiltration without any outbound connection to attacker-owned infrastructure).
6. A secondary DNS tunneling channel (`cloudlanecdn[.]com`) is used solely to receive refreshed Entra ID credentials after token expiry, keeping the implant's Entra authentication valid indefinitely.

### Why This Is Significant

- **No attacker-owned C2 visible**: All traffic goes to `graph.microsoft.com`, indistinguishable from normal M365 client activity at the IP and hostname level.
- **Detection requires URL-level inspection**: Only proxy solutions that log the full URI query string (including `$filter=` parameters) can see the `2050` dead-drop date indicator.
- **Exfiltration is invisible to DLP**: Files are uploaded as M365 calendar attachments — a path rarely monitored by DLP policies.
- **Operator pivot without malware recompile**: Updating the tasking requires only a calendar event update in M365; no change to the implant binary.

## IOCs

### Domains

| Indicator | Type | Context |
|-----------|------|---------|
| `cloudlanecdn[.]com` | Domain | HollowGraph secondary DNS C2; receives refreshed Entra ID credentials via DNS TXT record tunneling after token expiry; mimics a CDN provider |

### File Hashes

| Indicator | Type | Context |
|-----------|------|---------|
| `75e51774b8f79e5f256eaae639635f911b3e744d4774fd6068dd980255621509` | SHA256 | HollowGraph .NET DLL implant sample |
| `f3f3006f8304788251b153d53b305322b8acab0c66ec816b8d9f101bcc851da3` | SHA256 | HollowGraph .NET DLL implant sample (variant) |
| `b3d0f6e4e3be395fd7cf9e8101c89963d77216578cbb117a6ac9bc3564485eff` | SHA256 | HollowGraph .NET DLL implant sample (variant) |

### Graph API IOC

- **URI query string**: `?$filter=start/dateTime ge '2050-01-01'` — any Graph API calendar query containing `2050` in the `$filter` parameter is an unambiguous HollowGraph indicator. No legitimate calendar application queries events in 2050.
- **C2 event date**: `2050-05-13` — calendar event created/modified at this specific date is the operator's dead-drop event.

## MITRE ATT&CK TTPs

| Technique | ID | Notes |
|-----------|----|-------|
| Web Service: Bidirectional Communication | T1102.002 | M365 Graph API calendar used as two-way C2 dead drop |
| Application Layer Protocol: DNS | T1071.004 | DNS TXT tunnel for Entra credential refresh via `cloudlanecdn[.]com` |
| Exfiltration Over Alternative Protocol: DNS | T1048.001 | Secondary credential channel via DNS |
| Valid Accounts: Cloud Accounts | T1078.004 | Compromised Entra ID credentials used for Graph API authentication |
| Encrypted Channel: Symmetric Cryptography | T1573.001 | AES-256-GCM payload encryption |
| Encrypted Channel: Asymmetric Cryptography | T1573.002 | RSA key exchange for AES key delivery |
| Automated Collection | T1119 | `get` command collects files automatically |
| Automated Exfiltration | T1020 | `send` command uploads to calendar attachment without operator interaction |

## Kill Chain

- **Exploitation** — Entra ID credential compromise (assumed phishing/credential stuffing)
- **Installation** — HollowGraph DLL dropped and executed (delivery mechanism TBD)
- **Command & Control** — M365 calendar dead drop + DNS TXT credential channel
- **Actions on Objectives** — File collection and exfiltration via calendar attachment

## Attribution

- **Cavern Manticore** (Iran MOIS-linked) — High-confidence primary attribution by Group-IB; shared command syntax (`get`/`send`) and internal tasking structure match Cavern modular backdoor framework
- **Lyceum** (Iran-nexus) — Low-confidence infrastructure overlap; unconfirmed as of 2026-07-20

## Detection Coverage

A full detection has been written for HollowGraph: see `detections/command_and_control/hollowgraph_m365_calendar_c2.md`.

The detection covers six Splunk queries including:
1. Non-browser process accessing Graph API calendar endpoints
2. Graph API URL containing "2050" date IOC
3. M365 Unified Audit Log — calendar event created at 2050 date (operator planting tasking)
4. M365 Unified Audit Log — calendar attachment operations (exfiltration / tasking retrieval)
5. High-entropy DNS TXT queries (Entra credential tunnel)
6. Correlation rule — all three signals on same host within 15 minutes

## References

- [Group-IB — HollowGraph Iranian MOIS Calendar C2 (2026-07-20)](https://www.group-ib.com/resources/research-hub/hollowgraph-iranian-m365-calendar-c2/)
- [The Hacker News — HollowGraph Malware Hides C2 and Stolen Files in M365 Events Dated 2050 (2026-07-20)](https://thehackernews.com/2026/07/hollowgraph-malware-hides-c2-and-stolen.html)
- [BleepingComputer — New HollowGraph malware uses Microsoft Graph for stealthy C2 comms (2026-07-20)](https://www.bleepingcomputer.com/news/security/new-hollowgraph-malware-uses-microsoft-graph-for-stealthy-c2-comms/)
- [MITRE ATT&CK — T1102.002: Web Service: Bidirectional Communication](https://attack.mitre.org/techniques/T1102/002/)
- [MITRE ATT&CK — T1078.004: Valid Accounts: Cloud Accounts](https://attack.mitre.org/techniques/T1078/004/)
