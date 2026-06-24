# FortiBleed Campaign — FortiGate Mass Credential Harvesting

**Source:** SOCRadar, BleepingComputer  
**Date:** 2026-06-24  
**Attribution:** Russian-speaking threat actors (financially motivated)  
**Status:** ACTIVE; 430,000+ devices targeted since February 2026

## Summary

Russian-speaking threat actors are conducting a large-scale campaign targeting Fortinet FortiGate firewalls. Attackers exploit weak/default credentials or spray known passwords to gain admin access, then deploy custom network sniffers via FortiOS diagnostic CLI commands to harvest authentication credentials from passing network traffic.

## TTPs

### Initial Access (T1078.003 — Valid Accounts: Cloud Accounts / T1110.003 — Password Spraying)
- Credential spraying against FortiGate admin GUI (HTTPS) and SSL-VPN endpoints
- Brute-force of default passwords: admin/admin, admin/(blank), fortinet, fortigate
- No CVE required — exploitation of weak credentials

### Execution / Impact (T1040 — Network Sniffing)
1. Successful admin login to FortiGate
2. Execute `diagnose sniffer packet <interface> "tcp port 80 or port 443"` via CLI
3. Sniffer captures cleartext HTTP sessions, NTLM hashes from internal traffic
4. Harvested credentials used for internal lateral movement or sold

### Lateral Movement (T1021 — Remote Services)
- RDP/SMB access using harvested credentials to internal Windows hosts
- VPN session hijacking using captured session tokens

## Indicators

### Tactical IOCs (TTPs rather than specific hashes/IPs)
- FortiGate authentication from unusual geographies (RU, BY, KZ IP ranges)
- DIAG SNIFFER CLI command execution in FortiGate event logs
- Large number of auth failures followed by single successful login
- FortiGate CPU spike correlated with sniffer running

## MITRE ATT&CK

| Technique | Description |
|-----------|-------------|
| T1078 | Valid Accounts |
| T1110.003 | Brute Force: Password Spraying |
| T1040 | Network Sniffing |
| T1003 | OS Credential Dumping (from captured traffic) |
| T1021 | Remote Services (lateral movement with stolen creds) |

## Detection

Wazuh rules: 103604–103608

## Remediation

1. Enable two-factor authentication on all FortiGate admin accounts
2. Restrict admin access to management VLAN only (firewall policy)
3. Set account lockout after 5 failed attempts
4. Audit FortiGate event logs for `diagnose sniffer` command execution
5. Change all admin passwords and review all admin accounts
6. Verify FortiGate firmware is patched for any known CVEs
