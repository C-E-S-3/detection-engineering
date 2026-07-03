---
scraped_at: "2026-07-03T00:00:00Z"
source_url: "https://www.bleepingcomputer.com/news/security/fortibleed-credential-theft-campaign-linked-to-lynx-ransomware/"
report_type: threat-intel
severity: high
title: "FortiBleed credential-theft campaign linked to Lynx and INC ransomware via FortiGate Sniffer tool"
---

# FortiBleed Credential-Theft Campaign Linked to Lynx and INC Ransomware via FortiGate Sniffer Tool

**Source:** BleepingComputer / SOCRadar  
**Date:** 2026-07-02  
**Severity:** High  
**Tactic:** Credential Access (TA0006), Collection (TA0009), Exfiltration (TA0010)

---

## 1. IOCs

No public IOCs available at time of writing. SOCRadar full technical whitepaper with network indicators is forthcoming. This report will be updated when IOCs are released.

---

## 2. TTPs

### T1040 — Network Sniffing (Novel TTP)

The FortiBleed operators weaponize a **FortiOS built-in diagnostic command** to perform network sniffing without deploying a custom binary to the appliance:

```
diagnose sniffer packet <interface> '<filter>' <verbosity> <count> a
```

This command (`diagnose sniffer packet`) is a legitimate FortiOS CLI facility intended for troubleshooting. Operators with valid VPN credentials (harvested via the earlier brute-force phase) authenticate to the management CLI and execute multi-hour capture sessions targeting authentication traffic. The resulting capture contains VPN credentials, Active Directory NTLM hashes, and session tokens in cleartext or weakly-protected form.

A purpose-built Golang binary called **FortigateSniffer** automates this interaction:
- Authenticates to FortiOS CLI over SSH or the management API using a credential list
- Issues `diagnose sniffer packet` with per-appliance optimized filters
- Streams packet capture output back to operator infrastructure
- Parses captured traffic for credential material on-the-fly

**Why this matters:** Because the sniffer command is native to FortiOS, there is no binary drop, no file-system modification, and no exploit — the activity looks like authorized administrative troubleshooting. Traditional endpoint or file-system-based detections will miss it entirely. Detection requires FortiOS audit log correlation or network-level monitoring of management-plane traffic.

### T1003 — Credential Dumping (Derived from Capture)

Captured PCAP material is processed offline using **Hashtopolis** (distributed Hashcat orchestration) to crack NTLM hashes extracted from captured authentication exchanges. The operation uses a GPU cracking cluster consistent with a ~20-person operation, with cracking work distributed across cluster nodes.

### T1041 — Exfiltration Over C2 Channel

Credential material and cracked hashes are exfiltrated via operator infrastructure. No specific C2 domains or IPs have been published pending the SOCRadar whitepaper.

### Business-Hours Operational Pattern

Operator activity is concentrated between **07:00–18:00 Moscow Time (UTC+3)**, consistent with a professional Russian-speaking threat group operating during standard business hours. This pattern provides a behavioral detection opportunity — FortiOS management CLI access outside these hours from the same source IPs, or sustained multi-hour capture sessions, are anomalous.

---

## 3. Malware and Tools

| Tool | Type | Language | Description |
|------|------|----------|-------------|
| FortigateSniffer | Custom operator tool | Golang | Automates `diagnose sniffer packet` execution against credential lists; parses PCAP output for credential material |
| Hashtopolis | Open-source distributed cracking | Python/PHP | Distributed Hashcat orchestration; operators use it to distribute NTLM hash cracking across GPU cluster |
| Hashcat | Open-source cracking | C | GPU-accelerated hash cracking; used within Hashtopolis cluster |

---

## 4. Attribution

| Attribute | Detail |
|-----------|--------|
| Suspected Origin | Russian-speaking |
| Operation Size | ~20 persons |
| Working Hours | 07:00–18:00 MSK (UTC+3) |
| Ransomware Nexus | INC Ransom and Lynx ransomware panels |
| Relationship Type | FortiBleed operators provide harvested credentials/hashes to INC/Lynx affiliates for ransomware staging |

The campaign represents a **credential-supply pipeline**: FortiBleed actors harvest and crack VPN credentials at scale, then sell or transfer access to INC Ransom and Lynx ransomware operators who use those credentials for initial access into victim networks. This division-of-labor model is consistent with the Ransomware-as-a-Service ecosystem's increasing specialization.

INC Ransom has previously targeted healthcare and education sectors. Lynx is a rebrand of INC Ransom that emerged in 2024.

---

## 5. Splunk Detection Searches

See [FortiOS Diagnostic Sniffer Credential Capture](../detections/credential_access/fortios_diagnostic_sniffer_credential_capture.md) for the primary detection rule targeting this TTP.

---

## 6. Executive Summary

The FortiBleed campaign (first reported June 2026 for its brute-force phase) has a novel second-stage TTP: after gaining VPN credentials via automated password spraying, operators authenticate to FortiGate appliance management CLIs and execute the built-in `diagnose sniffer packet` command via a custom Golang tool (FortigateSniffer) to capture authentication traffic. Extracted NTLM hashes are cracked offline using a Hashtopolis/Hashcat GPU cluster. The harvested credentials feed a pipeline supplying INC Ransom and Lynx ransomware operators with ready-to-use enterprise access.

The critical defender implication is that this TTP leaves **no binary artifacts on the appliance**. Detection requires FortiOS audit log monitoring for `diagnose sniffer packet` execution, anomalous CLI session durations, or network-level visibility into FortiGate management-plane traffic.

---

## References

- [BleepingComputer — FortiBleed Linked to Lynx/INC Ransomware (2026-07-02)](https://www.bleepingcomputer.com/news/security/fortibleed-credential-theft-campaign-linked-to-lynx-ransomware/)
- [MITRE ATT&CK — T1040 Network Sniffing](https://attack.mitre.org/techniques/T1040/)
- [MITRE ATT&CK — T1003 OS Credential Dumping](https://attack.mitre.org/techniques/T1003/)
- [BleepingComputer — FortiBleed VPN Credential Leak (2026-06-xx)](https://www.bleepingcomputer.com/news/security/fortibleed-hackers-leaked-73932-fortigate-vpn-credentials/)
- [Hashtopolis — Distributed Hashcat](https://github.com/hashtopolis/server)
