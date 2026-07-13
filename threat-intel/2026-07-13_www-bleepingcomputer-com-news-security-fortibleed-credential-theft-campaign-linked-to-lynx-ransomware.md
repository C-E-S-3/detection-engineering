---
scraped_at: "2026-07-13T00:00:00Z"
source_url: "https://www.bleepingcomputer.com/news/security/fortibleed-credential-theft-campaign-linked-to-lynx-ransomware/"
report_type: threat-intel
severity: "critical"
title: "FortiBleed campaign attribution confirmed: IAB operators linked to Lynx and INC Ransom ransomware"
---

## 1. Indicators of Compromise (IOCs)

### IP Addresses
Previously tracked in ip.csv under FortiClient EMS/EKZ Stealer entry (2026-05-29): `83.138.53[.]110`

No new infrastructure IPs publicly released for this reporting cycle.

### Domains/URLs
None publicly released.

### File Hashes
None publicly released.

### Other IOCs
- **Backdoor account username:** `adminin` — unauthorized FortiOS administrator account created by threat actor to maintain persistent access after credential harvesting; consistent across confirmed compromises
- **FortiGate Sniffer tool indicators:**
  - Custom Golang-compiled binary (no public hash released)
  - Abuses FortiOS built-in diagnostic command: `diagnose sniffer packet all verbose 4`
  - Captures cleartext and hashed VPN authentication traffic passively from network interfaces

## 2. TTPs (MITRE ATT&CK Mapping)

- **T1040 — Network Sniffing** (Primary)
  - Threat actor deploys custom Golang tool ("FortigateSniffer") that invokes FortiOS's native `diagnose sniffer packet` diagnostic command to passively intercept SSL VPN authentication hashes and other credential material from live network traffic; tool avoids writing to disk on victim firewalls in most observed cases
- **T1110.002 — Brute Force: Password Cracking**
  - Intercepted Kerberos hashes and NTLMv2 authentication hashes cracked offline using a 45-GPU cluster; plaintext credentials then used for downstream access
- **T1078.002 — Valid Accounts: Domain Accounts**
  - Cracked credentials used to authenticate as legitimate AD users into victim environments; no vulnerability exploitation required at AD layer
- **T1136.001 — Create Account: Local Account**
  - "adminin" backdoor administrator account created in FortiOS after achieving admin access; provides persistent re-entry independent of stolen credential lifecycle
- **T1505.003 — Server Software Component: Web Shell**
  - Some victims showed evidence of web shell or management console backdoor implantation post-compromise on FortiGate management interfaces
- **T1486 — Data Encrypted for Impact**
  - FortiBleed IAB members confirmed to operate as affiliates of both Lynx RaaS and INC Ransom RaaS; at least 12 confirmed ransomware deployments across victim environments resulting from FortiBleed-sourced access
- **T1657 — Financial Theft / Ransom**
  - Ransomware deployed for double-extortion: encrypted files plus data theft exfiltration threat

## 3. Malware & Tools

### Tools
- **FortigateSniffer** — custom Golang binary; passively intercepts authentication traffic by abusing FortiOS `diagnose sniffer packet all <interface> verbose 4`; captures SSL VPN login hashes across multiple protocols including RADIUS, LDAP, Kerberos, and local auth
- **EKZ Stealer** — information stealer deployed via CVE-2026-35616 (FortiClient EMS, CVSS 9.1) in related FortiBleed sub-operations; harvests credentials from Chromium browsers and Firefox; exfiltrates via PowerShell

### Ransomware Families (downstream)
- **Lynx** — RaaS operation; double-extortion model; enterprise-targeting; operator-level access confirmed through recovered ransomware negotiation panel artifacts
- **INC Ransom** — RaaS operation; enterprise-targeting with documented healthcare, government, and manufacturing victims; separate negotiation panel access confirmed

## 4. Threat Actor / Campaign Attribution

- **Campaign name:** FortiBleed
- **Operator type:** Initial Access Broker (IAB); sells or directly leverages access for ransomware deployment
- **Organization scale:** Approximately 20-person operation based on recovered internal tracking documents; clear division of labor (scanning, harvesting, cracking, access brokering, ransomware deployment)
- **Attribution confidence:** Low-to-moderate for specific nation-state; financially motivated; Russian-speaking forum activity suspected but not confirmed
- **Ransomware links confirmed:** SOCRadar analysts recovered artifacts proving operators had access to active negotiation panels for both Lynx and INC Ransom RaaS platforms, directly linking FortiBleed access to ransomware deployment
- **Related CVE:** CVE-2026-35616 — FortiClient EMS (CVSS 9.1) SQL injection enabling RCE; exploited separately by same or related operators to deploy EKZ Stealer

### Campaign Scale (as of July 2026)
| Metric | Value |
|---|---|
| Hosts scanned | ~59,300,000 |
| FortiGate devices fingerprinted | ~437,000 |
| Credentials harvested | ~105,000,000 |
| Admin-level access confirmed | 409 organizations |
| Full attack chain completed | 354 organizations |
| Confirmed ransomware deployments | 12+ |
| Countries targeted | 150+ |

## 5. Splunk Detection Searches

**Note:** Dedicated FortiBleed detection rules already exist in this repo — see `detections/credential_access/fortibleed_vpn_credential_brute_force.md` and `detections/credential_access/fortios_diagnostic_sniffer_credential_capture.md`. The searches below supplement existing coverage with ransomware-chain-specific pivots.

### Detecting Lynx/INC Ransomware Deployment Post-FortiBleed

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Filesystem
  where Filesystem.file_name IN ("READ-ME.lynx.txt", "INC-README.txt", "*.lynx", "*.inc_encrypt")
  by Filesystem.dest Filesystem.user Filesystem.file_path Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=95
| table firstTime lastTime dest user file_path file_name risk_score
```
*Detects Lynx or INC Ransom ransom notes and encrypted file extensions; high-confidence ransomware deployment indicator.*

### Detecting 'adminin' Backdoor Account in FortiGate Logs

```spl
`fortigate`
  (action="create" OR action="add" OR eventtype="admin" OR subtype="admin")
  (user="adminin" OR admin="adminin" OR duser="adminin")
| stats count min(_time) as firstTime max(_time) as lastTime by host src_ip user action
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=90
| where risk_score >= 90
| table firstTime lastTime host src_ip user action risk_score
```
*Detects creation or use of the "adminin" backdoor FortiOS administrator account; high-confidence indicator of FortiBleed compromise.*

### Detecting Golang FortiGate Sniffer Execution via CLI Audit Logs

```spl
`fortigate`
  subtype="system" type="event"
  ("diagnose sniffer packet" AND "verbose 4")
| stats count min(_time) as firstTime max(_time) as lastTime by host src_ip user logdesc
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=85
| where risk_score >= 85
| table firstTime lastTime host src_ip user logdesc risk_score
```
*Detects execution of FortiOS diagnostic packet sniffer with verbose level 4, which is the specific invocation used by the FortigateSniffer Golang tool; legitimate admin use is possible but rare and warrants investigation.*

### Lateral Movement Using FortiBleed-Sourced VPN Credentials

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Authentication
  where Authentication.action="success" Authentication.app IN ("sslvpn", "forticlient", "ssl-vpn")
  by Authentication.dest Authentication.user Authentication.src Authentication.app
| `drop_dm_object_name(Authentication)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| join type=left user [
    | tstats `security_content_summariesonly` count
      from datamodel=Authentication
      where Authentication.action="failure"
      by Authentication.user
    | rename count as fail_count ]
| where isnull(fail_count) OR fail_count < 3
| eval risk_score=case(isnull(fail_count), 70, fail_count < 3, 60)
| where risk_score >= 60
| table firstTime lastTime dest user src app fail_count risk_score
```
*Detects successful SSL VPN authentication with no or minimal preceding failures, indicating stolen credential reuse rather than legitimate user login with MFA bypass.*

## 6. Executive Summary

The FortiBleed campaign, a large-scale financially motivated credential-theft operation targeting internet-facing Fortinet FortiGate SSL VPN devices, has been conclusively linked to the Lynx and INC Ransom ransomware-as-a-service (RaaS) operations. Attribution was established by SOCRadar (July 2, 2026) and subsequently confirmed across multiple intelligence sources following an operational security failure that exposed an IAB operator actively managing negotiation panels for both ransomware groups.

The campaign operates at industrial scale: a roughly 20-person organization uses a custom Golang-compiled packet sniffer ("FortigateSniffer") to abuse FortiOS's built-in `diagnose sniffer packet` diagnostic command, passively intercepting VPN authentication hashes from live network traffic. Harvested hashes are cracked offline with a 45-GPU cluster. Resulting plaintext credentials enable admin-level access without triggering authentication failure alerts. After establishing access, operators create the "adminin" backdoor FortiOS administrator account for persistence.

At least 12 ransomware deployments have been confirmed across victim environments. Affected organizations span healthcare, energy, manufacturing, government, and education sectors across 150+ countries. Defenders should prioritize detection of the "adminin" account creation, review FortiGate audit logs for `diagnose sniffer packet` invocations, and verify FortiClient EMS patching for CVE-2026-35616. Existing detection rules in `detections/credential_access/` provide primary coverage.

## References

- https://www.bleepingcomputer.com/news/security/fortibleed-credential-theft-campaign-linked-to-lynx-ransomware/
- https://socradar.io/blog/fortibleed-inc-lynx-ransomware-link/
- https://socradar.io/blog/fortibleed-fortinet-firewalls-compromised/
- https://thehackernews.com/2026/07/fortibleed-credential-theft-linked-to.html
- https://unit42.paloaltonetworks.com/large-scale-credential-attacks/
- https://www.securityweek.com/fortibleed-campaign-linked-to-inc-lynx-ransomware-attacks/
- https://attack.mitre.org/techniques/T1040/
- https://attack.mitre.org/techniques/T1486/
