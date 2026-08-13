# VMware vCenter reverse_ssh Cron Persistence (CVE-2026-59310 Post-Exploitation)

## Description

Detects deployment of `reverse_ssh` — an open-source reverse SSH tool — via a malicious cron job on a Linux host, consistent with post-exploitation persistence observed following CVE-2026-59310 exploitation against VMware vCenter Server Appliance (VCSA). Threat actors exploit CVE-2026-59310 (CVSS 9.8, directory traversal/RCE in the vCenter Syslog service, chained with CVE-2026-59309 auth bypass) to achieve unauthenticated RCE, then install reverse_ssh as a cron job for persistent outbound SSH access to attacker-controlled infrastructure.

This detection covers two signals:
1. **Process-based**: Execution of `reverse_ssh` or anomalous binaries spawned by the cron daemon
2. **Network-based**: Outbound SSH connections from vCenter appliance hosts or other Linux infrastructure hosts to external IPs

False positives are expected to be low for the `reverse_ssh` process name signal (legitimate use is almost exclusively in red team and homelab contexts). The cron anomaly signal may generate false positives from legitimate cron jobs spawning shells or non-standard scripts; tune by building an allowlist of expected cron job process names in the environment.

## MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| Tactic | Persistence |
| Tactic ID | TA0003 |
| Technique | Scheduled Task/Job: Cron |
| Technique ID | T1053.003 |
| Secondary Tactic | Command and Control |
| Secondary Tactic ID | TA0011 |
| Secondary Technique | Protocol Tunneling |
| Secondary Technique ID | T1572 |

## Lockheed Martin Kill Chain

| Phase |
|-------|
| Installation |
| Command & Control |

## Splunk Detection Query

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Processes
  where
    (Processes.process_name="reverse_ssh")
    OR
    (Processes.parent_process_name IN ("crond","cron","anacron")
     AND NOT Processes.process_name IN (
       "run-parts","sh","bash","dash","python","python3","perl",
       "sendmail","postfix","find","du","rm","rsync","logrotate",
       "vmware-tools","vmware-watchdog","vpxd","vpxd-svcs",
       "vmdird","vpostgres","vsandataservice","eam"
     ))
  by Processes.dest Processes.user Processes.parent_process_name
     Processes.process_name Processes.process Processes.process_id
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    process_name="reverse_ssh", 95,
    parent_process_name IN ("crond","cron","anacron")
      AND NOT match(process_name, "^(run-parts|sh|bash|dash|python3?|perl|sendmail|postfix|find|du|rm|rsync|logrotate)$"), 75,
    1=1, 50)
| where risk_score >= 75
| table firstTime lastTime dest user parent_process_name process_name process process_id risk_score
```

### Companion Query: Unusual Outbound SSH from Linux Infrastructure Hosts

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Network_Traffic.All_Traffic
  where All_Traffic.dest_port=22
    AND All_Traffic.transport="tcp"
    AND All_Traffic.action="allowed"
  by All_Traffic.src All_Traffic.dest All_Traffic.dest_port All_Traffic.app
| `drop_dm_object_name(All_Traffic)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| lookup vcenter_appliance_ips ip as src OUTPUT is_vcenter
| where is_vcenter="true"
| eval risk_score=case(
    NOT match(dest, "^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.)"), 90,
    1=1, 50)
| where risk_score >= 90
| table firstTime lastTime src dest dest_port app count risk_score
```

**Note:** The companion query requires a lookup `vcenter_appliance_ips` populated with management IPs of vCenter appliances. Alternatively, filter by known VCSA hostnames or subnet ranges used for management infrastructure.

## Risk Score Logic

| Condition | Score | Rationale |
|-----------|-------|-----------|
| `process_name="reverse_ssh"` | 95 | reverse_ssh by name is a high-confidence indicator; no legitimate enterprise use case for this binary |
| Anomalous binary spawned from crond/cron (not in expected allowlist) | 75 | Unexpected cron-spawned processes on Linux infrastructure warrant immediate review |
| Outbound SSH from VCSA to non-RFC1918 IP | 90 | vCenter appliances have no legitimate reason to initiate outbound internet SSH |

## Associated Threat Actors

| Actor | References |
|-------|-----------|
| Unattributed mass exploiters of CVE-2026-59310 | [Broadcom VMSA-2026-0006](https://www.broadcom.com/support/resources/security-center/security-advisories/vmsa-2026-0006); QUIRSO GmbH research |
| Ransomware pre-positioning actors | Historical VMware vCenter exploitation pattern (Cuba ransomware, ESXiArgs, etc.) |

## References

- [Broadcom VMSA-2026-0006 Security Advisory](https://www.broadcom.com/support/resources/security-center/security-advisories/vmsa-2026-0006)
- [Threat Intel: 2026-08-13_quirso-vmware-vcenter-cve-2026-59310-active-exploitation.md](../../threat-intel/2026-08-13_quirso-vmware-vcenter-cve-2026-59310-active-exploitation.md)
- [reverse_ssh open-source tool (GitHub)](https://github.com/NHAS/reverse_ssh)
- [MITRE ATT&CK: T1053.003 — Scheduled Task/Job: Cron](https://attack.mitre.org/techniques/T1053/003/)
- [MITRE ATT&CK: T1572 — Protocol Tunneling](https://attack.mitre.org/techniques/T1572/)
- [MITRE ATT&CK: T1190 — Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/)
