# FortiBleed: VPN Credential Brute Force and Password Spraying

## Description

Detects the brute-force and credential-stuffing pattern used in the FortiBleed campaign (disclosed June 17, 2026), where a Russian-speaking threat group conducted 1.16 billion credential attempts against 320,777 FortiGate VPN targets and 2.1 billion attempts against 163,650 MSSQL servers. The attackers operated a 45-GPU Hashtopolis cluster for offline NTLM/VPN hash cracking. The resulting dataset of 73,932 FortiGate VPN credentials (21,108 unique IPs, 8,316 unique domains across 194 countries) was publicly leaked. Approximately 50% of all internet-facing Fortinet firewalls indexed by Shodan were affected at disclosure.

The detection rules target the high-volume automated credential stuffing pattern: rapid successive failed authentication attempts from a single IP, and password spraying (same source, different target usernames). These patterns are generic SSH brute force patterns that also cover VPN and other network service auth failures when Wazuh receives those logs.

**Expected false positives:** Legitimate security scanner activity (internal vulnerability scans, Qualys/Nessus agents), misconfigured client retry loops, or high-turnover user pools with frequent lockouts.

## MITRE ATT&CK Mapping

| Tactic | Technique | ID |
|--------|-----------|-----|
| Credential Access | Brute Force: Password Guessing | T1110.001 |
| Credential Access | Brute Force: Password Spraying | T1110.003 |
| Credential Access | Brute Force: Password Cracking | T1110.002 |
| Lateral Movement | Valid Accounts | T1078 |
| Reconnaissance | Active Scanning: Scanning IP Blocks | T1595.001 |

## Lockheed Martin Kill Chain Phase

Reconnaissance, Exploitation (Credential Access)

## Wazuh Rule IDs

- **103040** — SSH brute force: 10+ failures from same IP in 60s (T1110.001, level 10)
- **103041** — SSH password spray: 5+ failures against different users from same IP in 60s (T1110.003, level 12)
- **103042** — SSH brute force escalation: 20+ failures from same IP in 120s (T1110.001, level 13)

## Splunk SPL Query

```spl
index=wazuh sourcetype=wazuh rule.id IN (103040,103041,103042)
| stats count as auth_failures, dc(data.dstuser) as unique_users by data.srcip, rule.description, _time
| where auth_failures > 5
| sort -auth_failures
| table _time, data.srcip, auth_failures, unique_users, rule.description
```

For VPN/FortiGate-specific (if Fortinet syslog forwarded to Wazuh):

```spl
index=wazuh sourcetype=fortinet OR sourcetype=wazuh
(rule.groups="authentication_failed" OR "VPN authentication failed")
| stats count as failures by src_ip, _time span=1m
| where failures > 20
| sort -failures
```

## Risk Score Logic

- 10+ failures/60s from same IP: Medium-High — possible automated tool
- 20+ failures/120s from same IP: High — almost certainly automated credential stuffing
- 5+ different users from same IP/60s: High — password spraying pattern; escalate immediately

## Associated Threat Actors

- **FortiBleed group**: Unnamed Russian-speaking multi-operator cybercriminal group; 73,932 FortiGate credentials leaked June 17, 2026; Hashtopolis GPU cluster for offline cracking; Shodan-enumerated targets.
- Generic brute force pattern also used by: Volt Typhoon, Scattered Spider, UNC4393 (BlackCat affiliates), and numerous financially-motivated ransomware groups during initial access phase.

## References

- https://www.bleepingcomputer.com/news/security/fortibleed-leak-exposes-fortinet-vpn-credentials-for-73-000-devices/
- https://attack.mitre.org/techniques/T1110/001/
- https://attack.mitre.org/techniques/T1110/003/
