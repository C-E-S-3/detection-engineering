---
scraped_at: 2026-06-18T00:00:00Z
source_url: https://www.bleepingcomputer.com/news/security/fortibleed-leak-exposes-fortinet-vpn-credentials-for-73-000-devices/
report_type: threat-intel
severity: high
title: "FortiBleed: Russian-Speaking Threat Group Leaks VPN Credentials for 73,932 FortiGate Devices"
---

## 1. IOCs

### Domains
None identified in public reporting. The attackers operated from compromised MSSQL and FortiGate infrastructure with no unique C2 domains attributed to this campaign.

### IP Addresses
No specific attacker C2 IPs have been publicly disclosed. Researchers noted the attackers used credential-stuffing infrastructure with a 45-GPU Hashtopolis cracking cluster; specifics are not public.

### File Hashes
None published.

### Other
- Exposed dataset: 73,932 FortiGate firewall VPN URLs with credentials (21,108 unique IPs, 8,316 unique domains)
- Threat actor cracking infrastructure: 45-GPU cluster orchestrated via Hashtopolis (offline cracking tool)

---

## 2. TTPs

| Tactic | Technique ID | Technique | Usage |
|--------|-------------|-----------|-------|
| Initial Access | T1110.001 | Brute Force: Password Guessing | ~1.16B credential attempts against 320,777 FortiGate targets |
| Initial Access | T1110.003 | Brute Force: Password Spraying | Parallel 2.1B brute-force attempts against 163,650 MSSQL servers |
| Credential Access | T1040 | Network Sniffing | SSL VPN authentication hashes intercepted mid-session |
| Credential Access | T1110.002 | Brute Force: Password Cracking | Offline NTLM/VPN hash cracking with 45-GPU Hashtopolis cluster |
| Lateral Movement | T1078 | Valid Accounts | Cracked credentials used to authenticate to Active Directory environments |
| Reconnaissance | T1595.001 | Active Scanning: Scanning IP Blocks | Internet-wide scan of exposed Fortinet instances via Shodan-indexed targets |

---

## 3. Malware & Tools

| Tool | Type | Notes |
|------|------|-------|
| Hashtopolis | Credential Cracking Orchestration | GPU cluster management for distributed offline hash cracking (open-source, weaponized) |

---

## 4. Threat Actor / Campaign Attribution

- **Threat Actor**: Unnamed Russian-speaking multi-operator cybercriminal group
- **Attribution**: Attribution to Russian-speaking operators based on operational tradecraft analysis by researcher Bob Diachenko and SOCRadar; no formal threat group name
- **Discovery**: June 17, 2026, by security researcher Bob Diachenko who discovered an exposed operational server belonging to the attackers
- **Campaign Scope**: 73,932 FortiGate firewalls in 194 countries; approximately 50% of all internet-facing Fortinet firewalls indexed by Shodan at time of disclosure; affected government, telecom, healthcare, education, financial services, and critical infrastructure
- **Fortinet's Statement**: Fortinet confirmed its investigation indicates credentials were obtained through **previous incidents and brute-force attacks** (not a newly disclosed vulnerability or breach)
- **Independent Validation**: Kevin Beaumont confirmed that some exposed admin logins and passwords are real and still valid

---

## 5. Splunk Detection Searches

```spl
| comment "FortiBleed: Detect anomalous FortiGate SSL-VPN authentication patterns consistent with credential-stuffing"
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Authentication
  where Authentication.action=failure Authentication.app="FortiGate*"
  by Authentication.src Authentication.dest Authentication.user Authentication.action
| `drop_dm_object_name(Authentication)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eventstats count as total_attempts by src
| where total_attempts >= 20
| eval risk_score=case(
    total_attempts >= 100, 85,
    total_attempts >= 50, 70,
    total_attempts >= 20, 55)
| where risk_score >= 55
| table firstTime lastTime src dest user total_attempts risk_score
```

```spl
| comment "FortiBleed: Detect successful FortiGate VPN login following large volume of failures from same source (credential stuffing success)"
`fortigate`
| search subtype=ssl type=event action=tunnel-up
| eval login_time=_time
| join src_ip [
    search `fortigate`
    | search subtype=ssl type=event action=tunnel-down status=failed
    | stats count as fail_count by src_ip
    | where fail_count >= 10]
| `security_content_ctime(login_time)`
| eval risk_score=90
| table login_time src_ip user tunnel_type risk_score
```

```spl
| comment "FortiBleed: Detect FortiGate admin panel authentication from unusual geographic regions or new source IPs"
`fortigate`
| search type=event logdesc="Admin login successful" OR logdesc="Admin login failed"
| stats count as attempts values(logdesc) as action_types by srcip user
| eval risk_score=case(
    match(action_types, "Admin login successful") AND attempts==1, 75,
    1=1, 40)
| where risk_score >= 75
| table _time srcip user action_types attempts risk_score
```

---

## 6. Executive Summary

On June 17, 2026, security researcher Bob Diachenko discovered an exposed attacker server containing VPN credentials for **73,932 FortiGate SSL-VPN devices** across 194 countries — comprising approximately 50% of all internet-facing Fortinet firewalls. The credential dataset was compiled by a Russian-speaking multi-operator cybercriminal group using a methodical three-stage operation: (1) systematic credential-stuffing using historical infostealer data (1.16 billion attempts against 320,777 FortiGate targets, plus 2.1 billion attempts against 163,650 MSSQL servers), (2) SSL VPN authentication hash interception, and (3) offline hash cracking via a 45-GPU Hashtopolis cluster.

Affected organizations include Chevron, Samsung, Foxconn, Comcast, AT&T, Mercedes-Benz, Toyota, and government entities. Fortinet confirmed no new vulnerability is involved — the credentials were obtained through previous incidents and brute-force attacks. Independent researcher Kevin Beaumont confirmed that some credentials remain valid.

**Immediate action required**: FortiGate operators should immediately review VPN access logs for anomalous sessions, enforce MFA for SSL-VPN, rotate all VPN credentials, and audit Active Directory for unauthorized activity from VPN authentication.
