# PEERSTITCH FortiGate ptrace Daemon Injection

## Description

Detects network and behavioral indicators of the PEERSTITCH memory-resident implant, which is injected into running FortiGate daemons (`miglogd` or `iked`) via Linux ptrace after exploitation of CVE-2024-47575 (FortiManager) or CVE-2025-61624 (FortiOS). PEERSTITCH leaves no binary on disk; it patches daemon function pointers in-place to hijack C2 communications through the daemon's existing network sockets.

Two detection approaches are provided: (1) network-based detection of outbound connections to known PEERSTITCH staging IPs, and (2) FortiManager log anomaly detection for CVE-2024-47575 unauthorized device registration events that precede PEERSTITCH deployment.

False positives for the IP-based detection are negligible — these are confirmed adversary IPs from Unit 42 research. The FortiManager unauthorized registration rule may generate alerts for legitimately misconfigured FortiGate devices attempting to register against the wrong manager; suppress by source IP after investigation.

## MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| Tactic | Defense Evasion |
| Tactic ID | TA0005 |
| Technique | Rootkit |
| Technique ID | T1014 |
| Secondary Technique | Process Injection: ptrace System Calls |
| Secondary Technique ID | T1055.008 |
| Initial Access Technique | Exploit Public-Facing Application |
| Initial Access Technique ID | T1190 |

## Lockheed Martin Kill Chain

| Phase |
|-------|
| Exploitation |
| Installation |
| Command & Control (C2) |

## Splunk Detection Query

### Rule 1 — Network Traffic to Known PEERSTITCH Staging IPs

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Network_Traffic.All_Traffic
where (All_Traffic.dest="23.240.77.233" OR All_Traffic.dest="47.18.167.159")
by All_Traffic.src All_Traffic.dest All_Traffic.dest_port All_Traffic.action
| `drop_dm_object_name(All_Traffic)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=90
| table firstTime lastTime src dest dest_port action risk_score
```

### Rule 2 — FortiManager Unauthorized Device Registration (CVE-2024-47575 Exploitation Pattern)

```spl
`fortimanager`
| where (event_type="device_registration" OR match(message, "(?i)(unauthorized|unregistered|unknown device|unmanaged)"))
    AND NOT (src_ip LIKE "10.%" OR src_ip LIKE "192.168.%" OR src_ip LIKE "172.1[6-9].%" OR src_ip LIKE "172.2%.%" OR src_ip LIKE "172.3[01].%")
| stats count min(_time) as firstTime max(_time) as lastTime by src_ip dest_ip serial_number device_id
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=85
| where risk_score >= 75
| table firstTime lastTime src_ip dest_ip serial_number device_id risk_score
```

## Risk Score Logic

| Condition | Score | Rationale |
|-----------|-------|-----------|
| Outbound connection to confirmed PEERSTITCH staging IP (23.240.77.233 or 47.18.167.159) | 90 | Published Unit 42 C2/staging infrastructure; no legitimate use expected |
| FortiManager receives registration from external (non-RFC1918) IP | 85 | CVE-2024-47575 exploitation pattern; production FortiGate devices are managed from internal IPs |

## Associated Threat Actors

| Actor | References |
|-------|-----------|
| CL-STA-0954 | [Unit 42 — PEERSTITCH FortiGate Implant (2026-10-14)](https://unit42.paloaltonetworks.com/fortimanager-cve-2024-47575-peerstitch-malware/) |

## References

- [Unit 42 — PEERSTITCH FortiGate Memory-Resident Implant (2026-10-14)](https://unit42.paloaltonetworks.com/fortimanager-cve-2024-47575-peerstitch-malware/)
- [Fortinet PSIRT — CVE-2024-47575 FortiManager Advisory](https://www.fortiguard.com/psirt/FG-IR-24-423)
- [MITRE ATT&CK — T1014 Rootkit](https://attack.mitre.org/techniques/T1014/)
- [MITRE ATT&CK — T1055.008 ptrace System Calls](https://attack.mitre.org/techniques/T1055/008/)
- [MITRE ATT&CK — T1190 Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/)
