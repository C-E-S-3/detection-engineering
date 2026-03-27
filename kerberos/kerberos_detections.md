# Kerberos Anomaly Detection Rules (Splunk SPL)

---

### Suspicious TGT Request - Offensive Tool TicketOptions Fingerprint (Rubeus, Impacket, Certipy, Whisker)

Offensive tools such as Rubeus, Impacket, Certipy, and Whisker produce TGT requests with hardcoded TicketOptions values that are missing the Canonicalize flag (bit 15). The hex value `0x40800010` (Forwardable, Renewable, Renewable-ok) is the default for Rubeus and several Impacket modules. Legitimate Windows TGT requests almost always include the Canonicalize flag, making its absence a high-fidelity indicator of tool usage. This detection targets Event ID 4768 (TGT request) on Domain Controllers.

**MITRE ATT&CK:** T1558 - Steal or Forge Kerberos Tickets

**Reference:** [NVISO - Hunting Kerberos: Decode TGT TicketOptions with KQL](https://blog.nviso.eu/2026/02/12/capture-the-kerberos-flag-detecting-kerberos-anomalies/)

```
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

---

### Suspicious TGT Request - Metasploit TicketOptions Fingerprint

Metasploit's Kerberos client module (`Msf::Exploit::Remote::Kerberos::Client::AsRequest`) produces TGT requests with TicketOptions value `0x50800000`, representing flags Forwardable, Proxiable, and Renewable. The Proxiable flag (bit 3) combined with the absence of Canonicalize (bit 15) is extremely rare in legitimate Windows environments and is a strong indicator of Metasploit usage.

**MITRE ATT&CK:** T1558 - Steal or Forge Kerberos Tickets

**Reference:** [NVISO - Hunting Kerberos: Decode TGT TicketOptions with KQL](https://blog.nviso.eu/2026/02/12/capture-the-kerberos-flag-detecting-kerberos-anomalies/)

```
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

---

### TGT Request Missing Canonicalize Flag - Bitwise Analysis

Rather than relying on static hex values that attackers can modify, this detection uses bitwise analysis to identify any TGT request where the Canonicalize flag (bit 15) is absent. This catches both known tool signatures and novel TicketOptions values. The approach uses Splunk's `tonumber()` to convert the hex TicketOptions and a modulo/division-based bit check to test bit 15. In MSB-0 numbering, bit 15 corresponds to `0x00010000` (decimal 65536).

**MITRE ATT&CK:** T1558 - Steal or Forge Kerberos Tickets

**Reference:** [NVISO - Hunting Kerberos: Decode TGT TicketOptions with KQL](https://blog.nviso.eu/2026/02/12/capture-the-kerberos-flag-detecting-kerberos-anomalies/)

```
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

---

### Kerberoasting - TGS Request with RC4 Encryption

Kerberoasting attacks request Kerberos service tickets (TGS) for accounts with Service Principal Names (SPNs) and specifically request RC4 encryption (`0x17`) because it is significantly faster to crack offline than AES. This detection monitors Event ID 4769 for TGS requests using RC4 encryption targeting non-machine service accounts, with TicketOptions values commonly observed in Kerberoasting tools.

**MITRE ATT&CK:** T1558.003 - Kerberoasting

**Reference:** [Splunk - Detecting Active Directory Kerberos Attacks](https://www.splunk.com/en_us/blog/security/detecting-active-directory-kerberos-attacks-threat-research-release-march-2022.html)

```
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

---

### Kerberoasting - Anomalous Volume of TGS Requests

Kerberoasting tools typically enumerate all SPNs in the domain and request service tickets for each one in rapid succession. This detection identifies accounts requesting an unusually high number of distinct service tickets within a short time window using statistical analysis (3-sigma rule). A normal user rarely requests more than a handful of unique service tickets in an hour.

**MITRE ATT&CK:** T1558.003 - Kerberoasting

**Reference:** [Splunk Security Content - Unusual Number of Kerberos Service Tickets Requested](https://research.splunk.com/endpoint/eb3e6702-8936-11ec-98fe-acde48001122/)

```
`wineventlog_security` EventCode=4769
| where Service_Name!="krbtgt" AND Service_Name!="*$"
| bin _time span=1h
| stats dc(Service_Name) as unique_services count as total_requests
    values(Service_Name) as targeted_services values(Ticket_Encryption_Type) as encryption_types
    by Account_Name Client_Address _time
| eventstats avg(unique_services) as avg_services stdev(unique_services) as stdev_services
    by Account_Name
| eval threshold=avg_services + (3 * stdev_services)
| eval threshold=if(threshold < 10, 10, threshold)
| where unique_services > threshold OR unique_services > 15
| eval has_rc4=if(match(encryption_types, "0x17"), 1, 0)
| eval risk_score=case(
    unique_services > 50 AND has_rc4=1, 95,
    unique_services > 50, 85,
    unique_services > 20 AND has_rc4=1, 85,
    unique_services > 20, 75,
    has_rc4=1, 70,
    1=1, 60)
| sort - risk_score
| table _time Account_Name Client_Address unique_services total_requests encryption_types avg_services threshold targeted_services risk_score
```

---

### AS-REP Roasting - TGT Request Without Pre-Authentication

AS-REP Roasting targets accounts with Kerberos pre-authentication disabled (DONT_REQUIRE_PREAUTH). When this is set, the KDC returns an encrypted TGT without verifying the requester's identity, allowing offline password cracking. This detection monitors Event ID 4768 for successful TGT requests where the Pre-Authentication Type is `0` (disabled), especially when combined with RC4 encryption.

**MITRE ATT&CK:** T1558.004 - AS-REP Roasting

**Reference:** [Microsoft - Event 4768 Documentation](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4768)

```
`wineventlog_security` EventCode=4768 Pre_Authentication_Type=0 Status=0x0
| eval is_rc4=if(Ticket_Encryption_Type="0x17", 1, 0)
| eval is_des=if(Ticket_Encryption_Type="0x03" OR Ticket_Encryption_Type="0x01", 1, 0)
| eval risk_score=case(
    is_rc4=1, 90,
    is_des=1, 95,
    1=1, 70)
| stats count min(_time) as firstTime max(_time) as lastTime
    values(Ticket_Encryption_Type) as encryption_types values(Ticket_Options) as ticket_options
    by Account_Name Client_Address Service_Name risk_score
| where Account_Name!="*$"
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| sort - risk_score
| table firstTime lastTime Account_Name Client_Address Service_Name encryption_types ticket_options count risk_score
```

---

### AS-REP Roasting - High Volume Targeting Multiple Accounts

Attackers using tools like Rubeus's `asreproast` command or Impacket's `GetNPUsers.py` will enumerate and request AS-REPs for all accounts with pre-authentication disabled. This detection identifies a single source IP requesting TGTs without pre-authentication for multiple distinct accounts, which is a strong indicator of AS-REP Roasting enumeration.

**MITRE ATT&CK:** T1558.004 - AS-REP Roasting

```
`wineventlog_security` EventCode=4768 Pre_Authentication_Type=0 Status=0x0
| bin _time span=30m
| stats dc(Account_Name) as unique_accounts count as total_requests
    values(Account_Name) as targeted_accounts values(Ticket_Encryption_Type) as encryption_types
    by Client_Address _time
| where unique_accounts >= 3
| eval has_rc4=if(match(encryption_types, "0x17"), 1, 0)
| eval risk_score=case(
    unique_accounts >= 10 AND has_rc4=1, 95,
    unique_accounts >= 10, 90,
    unique_accounts >= 5 AND has_rc4=1, 85,
    unique_accounts >= 5, 80,
    has_rc4=1, 75,
    1=1, 70)
| sort - risk_score
| table _time Client_Address unique_accounts total_requests targeted_accounts encryption_types risk_score
```

---

### OverPass-the-Hash / Pass-the-Key - TGT Request with RC4 Encryption

An OverPass-the-Hash attack occurs when an adversary uses a stolen NTLM hash to request a Kerberos TGT via RC4 encryption instead of using the account's actual password. In modern environments where AES is the default, a TGT request (Event 4768) using RC4 encryption (`0x17`) is anomalous and may indicate this attack. This is especially suspicious when the request originates from a workstation rather than a legacy server.

**MITRE ATT&CK:** T1550.002 - Pass the Hash

**Reference:** [Splunk Security Content - Kerberos TGT Request Using RC4 Encryption](https://research.splunk.com/endpoint/18916468-9c04-11ec-bdc6-acde48001122/)

```
`wineventlog_security` EventCode=4768 Ticket_Encryption_Type=0x17 Status=0x0
| where Account_Name!="*$"
| eval ticket_opts_dec=tonumber(replace(Ticket_Options, "^0x", ""), 16)
| eval canonicalize_set=if((floor(ticket_opts_dec / 65536) % 2) == 1, 1, 0)
| eval risk_score=case(
    canonicalize_set=0, 90,
    1=1, 75)
| stats count min(_time) as firstTime max(_time) as lastTime
    values(Ticket_Options) as ticket_options values(Account_Name) as accounts
    by Client_Address Ticket_Encryption_Type risk_score canonicalize_set
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| sort - risk_score
| table firstTime lastTime Client_Address accounts Ticket_Encryption_Type ticket_options canonicalize_set count risk_score
```

---

### Golden Ticket - TGT Request with Deprecated Encryption (DES/RC4) for Privileged Account

Golden Ticket attacks involve forging a TGT using the KRBTGT account's hash. Offensive tools often default to RC4 or even DES encryption when forging tickets. This detection looks for TGT requests with weak encryption for accounts that are typically targeted in Golden Ticket attacks (Domain Admins, Enterprise Admins), or for any TGT with DES encryption which is almost certainly malicious in modern environments.

**MITRE ATT&CK:** T1558.001 - Golden Ticket

```
`wineventlog_security` EventCode=4768 Status=0x0
    (Ticket_Encryption_Type=0x17 OR Ticket_Encryption_Type=0x03 OR Ticket_Encryption_Type=0x01)
| where Account_Name!="*$"
| eval is_des=if(Ticket_Encryption_Type="0x03" OR Ticket_Encryption_Type="0x01", 1, 0)
| eval risk_score=case(
    is_des=1, 95,
    Ticket_Encryption_Type="0x17", 75,
    1=1, 60)
| eval ticket_opts_dec=tonumber(replace(Ticket_Options, "^0x", ""), 16)
| eval canonicalize_set=if((floor(ticket_opts_dec / 65536) % 2) == 1, 1, 0)
| eval risk_score=if(canonicalize_set=0, risk_score + 15, risk_score)
| stats count min(_time) as firstTime max(_time) as lastTime
    values(Ticket_Options) as ticket_options
    by Account_Name Client_Address Service_Name Ticket_Encryption_Type risk_score canonicalize_set
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| sort - risk_score
| table firstTime lastTime Account_Name Client_Address Service_Name Ticket_Encryption_Type ticket_options canonicalize_set count risk_score
```

---

### Silver Ticket - TGS Request Without Preceding TGT

A Silver Ticket is a forged Kerberos TGS ticket. Because the attacker forges the service ticket directly using the service account's hash, there is no corresponding TGT request (Event 4768) on the Domain Controller. This detection looks for TGS events (4769) for user accounts where no corresponding TGT was issued within a lookback window, which may indicate a forged service ticket.

**MITRE ATT&CK:** T1558.002 - Silver Ticket

```
`wineventlog_security` EventCode=4769
| where Service_Name!="krbtgt" AND Account_Name!="*$"
| rename Account_Name as tgs_account Client_Address as tgs_client
| join type=left tgs_account tgs_client
    [search `wineventlog_security` EventCode=4768 Status=0x0
     | rename Account_Name as tgs_account Client_Address as tgs_client
     | stats max(_time) as last_tgt_time by tgs_account tgs_client]
| eval tgt_age=_time - last_tgt_time
| eval has_tgt=if(isnotnull(last_tgt_time), 1, 0)
| where has_tgt=0 OR tgt_age > 86400
| eval risk_score=case(
    has_tgt=0, 90,
    tgt_age > 86400, 70,
    1=1, 60)
| eval risk_reason=case(
    has_tgt=0, "No preceding TGT found - possible Silver Ticket",
    tgt_age > 86400, "TGT older than 24h - possible ticket reuse or forgery",
    1=1, "Anomalous TGS request")
| stats count min(_time) as firstTime max(_time) as lastTime
    values(Service_Name) as services values(Ticket_Encryption_Type) as encryption_types
    values(risk_reason) as risk_reason
    by tgs_account tgs_client risk_score
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| sort - risk_score
| table firstTime lastTime tgs_account tgs_client services encryption_types risk_reason count risk_score
```

---

### Kerberos Pre-Authentication Brute Force / Password Spray

A high volume of Kerberos pre-authentication failures (Event ID 4771) from a single source IP targeting multiple accounts within a short window is a strong indicator of password spraying or brute-force attacks. Event 4771 is generated when pre-authentication fails, typically due to an incorrect password (Status `0x18`) or account not found (Status `0x6`).

**MITRE ATT&CK:** T1110.003 - Password Spraying, T1110.001 - Password Guessing

```
`wineventlog_security` EventCode=4771
    (Status=0x18 OR Status=0x6)
| bin _time span=15m
| stats dc(Account_Name) as unique_accounts count as total_failures
    values(Account_Name) as targeted_accounts values(Status) as failure_codes
    by Client_Address _time
| eval has_bad_password=if(match(failure_codes, "0x18"), 1, 0)
| eval has_unknown_user=if(match(failure_codes, "0x6"), 1, 0)
| eval risk_score=case(
    unique_accounts >= 20 AND has_bad_password=1, 95,
    unique_accounts >= 10 AND has_bad_password=1, 90,
    unique_accounts >= 20 AND has_unknown_user=1, 85,
    unique_accounts >= 5 AND has_bad_password=1, 80,
    total_failures >= 50, 80,
    unique_accounts >= 5, 70,
    1=1, 60)
| where unique_accounts >= 5 OR total_failures >= 20
| sort - risk_score
| table _time Client_Address unique_accounts total_failures failure_codes targeted_accounts risk_score
```

---

### ADCS Abuse - Certificate-Based TGT with Suspicious TicketOptions

Active Directory Certificate Services (ADCS) attacks (e.g., ESC1-ESC8 via Certipy or Certify) result in TGT requests with Pre-Authentication Type 16 (certificate-based). When combined with TicketOptions starting with `0x4080` (missing Canonicalize flag), this is a high-confidence indicator of ADCS exploitation since this hex prefix is hardcoded in Certipy, Rubeus, and other ADCS attack tools.

**MITRE ATT&CK:** T1649 - Steal or Forge Authentication Certificates

**Reference:** [SOC Stories - Detecting ADCS Attacks](https://www.socstories.blog/detecting-adcs-attacks/)

```
`wineventlog_security` EventCode=4768 Pre_Authentication_Type=16
| eval ticket_opts_str=Ticket_Options
| where match(ticket_opts_str, "^0x4080")
| eval risk_score=90
| eval detection_detail="Certificate-based TGT with tool-fingerprinted TicketOptions (0x4080*) - likely ADCS exploitation (Certipy/Rubeus/Certify)"
| stats count min(_time) as firstTime max(_time) as lastTime
    values(Ticket_Encryption_Type) as encryption_types
    by Account_Name Client_Address Service_Name Ticket_Options detection_detail risk_score
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| table firstTime lastTime Account_Name Client_Address Service_Name Ticket_Options encryption_types detection_detail count risk_score
```

---

### Kerberos Anomaly Baseline - Rare TicketOptions Discovery

This is a hunting query rather than an alerting rule. It identifies TicketOptions values that deviate from the environment baseline by finding rare hex values across all TGT requests. This helps discover novel tool signatures, misconfigured systems, or attacker customization that evades static-value detections. Run periodically and investigate any new or rare TicketOptions values that appear.

**MITRE ATT&CK:** T1558 - Steal or Forge Kerberos Tickets

```
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

---

### Kerberos Encryption Downgrade - TGS Request with DES Encryption

DES encryption types (`0x03` DES-CBC-MD5 and `0x01` DES-CBC-CRC) are deprecated and disabled by default in modern Windows environments. Any Kerberos service ticket request using DES encryption is almost certainly the result of a misconfigured legacy system or an attacker using outdated tooling. This detection has very few false positives in environments where DES is properly disabled.

**MITRE ATT&CK:** T1558 - Steal or Forge Kerberos Tickets

```
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
