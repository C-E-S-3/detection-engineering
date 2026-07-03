# FortiOS Diagnostic Sniffer Credential Capture

## Description

Detects execution of the FortiOS built-in `diagnose sniffer packet` command via the management CLI, which FortiBleed operators abuse to capture authentication traffic and extract VPN credentials and NTLM hashes without deploying any binary to the appliance. Because the command is a legitimate FortiOS troubleshooting facility, it produces no file-system artifacts; detection depends entirely on FortiOS audit log monitoring.

Legitimate use of `diagnose sniffer packet` is uncommon in production environments and is almost exclusively limited to short-duration troubleshooting sessions by authorized network engineers. Sustained sessions (>5 minutes), sessions targeting authentication-bearing interfaces (ssl.root, port1), or sessions initiated from unexpected source IPs (non-management workstations) should be treated as high-confidence malicious activity.

False positives may arise from authorized network engineers performing packet capture during incident response or network troubleshooting. Baseline authorized users and management workstation IPs, then alert on deviations.

## MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| Tactic | Credential Access |
| Tactic ID | TA0006 |
| Technique | Network Sniffing |
| Technique ID | T1040 |

## Lockheed Martin Kill Chain

| Phase |
|-------|
| Actions on Objectives |

## Splunk Detection Query

```spl
`fortigate`
| search message="*diagnose sniffer packet*" OR log_subtype="admin" action="executed" command="*diagnose sniffer*"
| eval session_duration_min=round((latest_time - earliest_time) / 60, 1)
| stats
    count as cmd_count
    min(_time) as firstTime
    max(_time) as lastTime
    values(src_ip) as src_ips
    values(user) as users
    values(command) as commands
    by host
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    cmd_count >= 10, 95,
    cmd_count >= 3,  80,
    1=1,             65)
| where risk_score >= 65
| table firstTime lastTime host users src_ips commands cmd_count risk_score
```

**Supplemental — sustained capture session detection:**

```spl
`fortigate`
| search log_subtype="admin" (command="*sniffer*" OR message="*sniffer packet*")
| bin _time span=1m
| stats count as events_per_min by _time host user src_ip
| eventstats sum(events_per_min) as total_events dc(_time) as session_minutes by host user src_ip
| where session_minutes >= 5
| eval risk_score=case(
    session_minutes >= 30, 95,
    session_minutes >= 10, 85,
    session_minutes >= 5,  75)
| stats
    min(_time) as firstTime
    max(_time) as lastTime
    values(risk_score) as risk_scores
    max(session_minutes) as session_minutes
    max(total_events) as total_events
    by host user src_ip
| eval risk_score=mvmax(risk_scores)
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| table firstTime lastTime host user src_ip session_minutes total_events risk_score
```

**Note:** Replace `` `fortigate` `` with the appropriate source macro for your FortiGate log integration (e.g., `` `fortigate_syslog` ``, `` `fortigate_hec` ``). The field names `log_subtype`, `command`, `src_ip`, `user`, and `host` follow the FortiGate Unified Logging schema. Adjust field names to match your Splunk TA normalization.

## Risk Score Logic

| Condition | Score | Rationale |
|-----------|-------|-----------|
| Single `diagnose sniffer packet` execution (any) | 65 | Rare in production; always warrants investigation |
| 3+ sniffer commands in session | 80 | Consistent with iterating across interfaces; strong indicator of FortiBleed TTP |
| 10+ sniffer commands in session | 95 | Automated tool behavior (FortigateSniffer Golang binary iterating credential list) |
| Sniffer session lasting 5+ minutes | 75 | Captures authentication traffic over time; distinguishes operator sessions from one-shot troubleshooting |
| Sniffer session lasting 10+ minutes | 85 | High-confidence credential harvesting operation |
| Sniffer session lasting 30+ minutes | 95 | Near-certain automated credential capture |

## Associated Threat Actors

| Actor | References |
|-------|-----------|
| FortiBleed Campaign Operators (Russian-speaking, linked to Lynx/INC Ransom) | [BleepingComputer — FortiBleed Lynx Link (2026-07-02)](https://www.bleepingcomputer.com/news/security/fortibleed-credential-theft-campaign-linked-to-lynx-ransomware/) |
| INC Ransom | [CISA — INC Ransom Advisory](https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-242a) |
| Lynx Ransomware | [BleepingComputer — Lynx Ransomware](https://www.bleepingcomputer.com/news/security/new-lynx-ransomware-emerges-as-a-rebrand-of-inc-ransomware/) |

## References

- [BleepingComputer — FortiBleed Linked to Lynx and INC Ransomware (2026-07-02)](https://www.bleepingcomputer.com/news/security/fortibleed-credential-theft-campaign-linked-to-lynx-ransomware/)
- [MITRE ATT&CK — T1040 Network Sniffing](https://attack.mitre.org/techniques/T1040/)
- [FortiOS CLI Reference — diagnose sniffer packet](https://docs.fortinet.com/document/fortigate/7.4.0/cli-reference/72622/diagnose-sniffer-packet)
- [Threat Intel Report](../../threat-intel/2026-07-03_www-bleepingcomputer-com-news-security-fortibleed-linked-to-lynx-inc-ransomware.md)
