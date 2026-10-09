---
scraped_at: "2026-10-09T00:00:00Z"
source_url: "https://www.ic3.gov/CSA/2026/261007-fortibleed.pdf"
report_type: threat-intel
severity: high
title: "FBI/Secret Service Joint Advisory: FortiBleed Campaign Active Against 86,644 Fortinet Devices — Now Linked to Payload Ransomware"
---

## 1. IOCs

No new IPs or domains published in this advisory. Prior FortiBleed IOC sets remain valid (tracked in `threat-intel/2026-07-03` and `threat-intel/2026-07-13`).

### Key Statistics

| Metric | Value |
|--------|-------|
| Compromised devices | 86,644 Fortinet FortiGate/SSL-VPN targets |
| Countries affected | 194 |
| Linked ransomware families | INC, Lynx, **Payload** (new) |
| Advisory date | October 6–7, 2026 |
| Issuing agencies | FBI, US Secret Service |

---

## 2. TTPs (MITRE ATT&CK)

| Tactic | Technique ID | Technique Name | Usage |
|--------|-------------|----------------|-------|
| Reconnaissance | T1595.001 | Active Scanning: Scanning IP Blocks | Mass scanning of internet-facing FortiGate VPN portals using Shodan-correlated targeting |
| Credential Access | T1110.001 | Brute Force: Password Guessing | Credential stuffing using leaked infostealer log credential sets against FortiGate VPN portals |
| Credential Access | T1110.003 | Brute Force: Password Spraying | Password spraying with common credentials and account-lockout-aware timing |
| Credential Access | T1110.002 | Brute Force: Password Cracking | Distributed GPU cluster (Hashtopolis) used for offline cracking of stolen VPN password hashes |
| Persistence | T1098 | Account Manipulation | Creation of new administrative accounts on compromised Fortinet devices to maintain access after credential rotation |
| Discovery | T1018 | Remote System Discovery | Active Directory enumeration via compromised VPN credential to map internal network for ransomware staging |
| Defense Evasion | T1070.006 | Indicator Removal: Timestomp | Some operators changed admin passwords or deleted legitimate accounts to lock out defenders |
| Impact | T1486 | Data Encrypted for Impact | INC, Lynx, and Payload ransomware deployment following credential-based VPN access |

---

## 3. Malware & Tools

| Tool | Type | Description |
|------|------|-------------|
| Hashtopolis cluster | Cracking Infrastructure | Distributed GPU cluster (45+ GPUs documented) used to crack VPN password hashes offline at scale |
| INC Ransomware | Ransomware | RaaS affiliate using stolen VPN credentials for initial access; exfiltrates then encrypts |
| Lynx Ransomware | Ransomware | RaaS affiliate using FortiBleed credential pipeline for initial access |
| Payload Ransomware | Ransomware | **New link documented in October 2026 advisory**; uses FortiBleed credential pipeline; ransomware family previously associated with targeted manufacturing and healthcare sectors |

---

## 4. Threat Actor / Campaign Attribution

The FortiBleed campaign involves multiple operators: credential harvesters sell access or supply stolen credential sets to ransomware affiliates operating INC, Lynx, and Payload. The credential-theft stage is primarily attributed to a Russian-speaking group with GPU cracking infrastructure. Downstream ransomware operators vary and should be treated as distinct.

---

## 5. Splunk Detection Searches

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Authentication
  where Authentication.action="failure"
    AND Authentication.app IN ("VPN","FortiGate","Fortinet SSL VPN","FortiClient")
  by Authentication.src Authentication.dest Authentication.user
| `drop_dm_object_name(Authentication)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| stats count as failures dc(user) as distinct_users
    min(firstTime) as firstTime max(lastTime) as lastTime
    by src dest
| where failures > 20 OR distinct_users > 5
| eval risk_score=case(distinct_users > 20, 90, distinct_users > 5, 75, failures > 50, 80, 1=1, 60)
| where risk_score >= 60
| table firstTime lastTime src dest failures distinct_users risk_score
```

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Change
  where Change.object_category="user"
    AND Change.action="created"
    AND Change.app IN ("FortiGate","Fortinet","FortiOS")
  by Change.dest Change.user Change.src Change.object
| `drop_dm_object_name(Change)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=90
| table firstTime lastTime dest user src object risk_score
```

---

## 6. Executive Summary

The FBI and US Secret Service issued a joint advisory on October 6–7, 2026 warning that the **FortiBleed** campaign remains actively harvesting credentials from internet-facing Fortinet FortiGate firewalls and SSL VPN gateways. At the time of advisory, operators had compromised **86,644 devices** across **194 countries** by credential stuffing with infostealer-sourced credential lists, cracking harvested VPN password hashes with a distributed GPU cluster, and then creating new admin accounts for persistence.

This advisory notably adds **Payload ransomware** to the list of downstream operators (previously only INC and Lynx were linked). Some victims have been locked out of their own devices when attackers deleted legitimate administrator accounts during intrusion cleanup.

The advisory recommends:
1. Terminate all active VPN and admin sessions immediately.
2. Reset all admin and user credentials.
3. Enable phishing-resistant MFA on VPN and management interfaces.
4. Migrate credential storage to PBKDF2 and remove weaker legacy SHA-256 hashes from configuration.
5. Audit for any newly created admin accounts not provisioned through standard processes.
6. Treat any FortiGate device that appeared in the leaked FortiBleed credential datasets as fully compromised until verified clean.
