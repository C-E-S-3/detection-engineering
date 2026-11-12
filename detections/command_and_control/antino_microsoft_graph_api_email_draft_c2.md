# Antino / UAT-11587: Microsoft Graph API Email Draft Dead-Drop C2

## Description

Detects non-email-client processes making repeated outbound HTTPS connections to `graph.microsoft.com`, indicating potential use of Microsoft 365 email drafts or OneDrive as a command-and-control dead-drop channel. This technique, observed in the Antino Rust backdoor deployed by UAT-11587 (China-nexus), authenticates to Microsoft Graph API using OAuth tokens and reads operator commands written to a designated Outlook folder every 10 seconds. Exfiltration occurs via the same channel or via OneDrive.

False positive sources include custom line-of-business applications, automation scripts, and third-party SaaS connectors that use the Microsoft Graph API. These should be allowlisted by process name or service account identity after validation.

## MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| Tactic | Command and Control |
| Tactic ID | TA0011 |
| Technique | Web Service: Bidirectional Communication |
| Technique ID | T1102.002 |
| Secondary Technique | Web Service: One-Way Communication (OneDrive variant) |
| Secondary Technique ID | T1102.001 |
| Sub-technique | — |

Secondary tactics: Exfiltration (T1567.002 — Exfiltration to Cloud Storage)

## Lockheed Martin Kill Chain Phase

| Phase | Applies |
|-------|---------|
| Reconnaissance | No |
| Weaponization | No |
| Delivery | No |
| Exploitation | No |
| Installation | No |
| Command & Control (C2) | **Yes** |
| Actions on Objectives | No |

## Splunk Detection Query

### Primary: Anomalous Process Contacting graph.microsoft.com

```spl
`sysmon`
(EventCode=3 OR EventCode=22)
dest_hostname="graph.microsoft.com"
NOT (process_name IN ("outlook.exe","teams.exe","OneDrive.exe","msedge.exe",
                       "chrome.exe","firefox.exe","msedgewebview2.exe",
                       "SearchIndexer.exe","lsass.exe","MicrosoftEdge.exe",
                       "SystemSettings.exe","WinStore.App.exe"))
| stats count min(_time) as firstTime max(_time) as lastTime by host user process_name process_id dest_hostname
| where count >= 5
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(count >= 100, 85, count >= 20, 70, count >= 5, 55, 1=1, 40)
| where risk_score >= 55
| table firstTime lastTime host user process_name process_id dest_hostname count risk_score
```

### Secondary: High-Frequency Graph API Polling (Antino 10s Interval)

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Network_Traffic.All_Traffic
where All_Traffic.dest_host="graph.microsoft.com" All_Traffic.dest_port=443
  AND NOT All_Traffic.app IN ("outlook","microsoft-teams","onedrive","browser")
by All_Traffic.src All_Traffic.dest_host All_Traffic.app All_Traffic.user
| `drop_dm_object_name(All_Traffic)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval session_minutes=round((lastTime-firstTime)/60,1)
| eval polls_per_minute=round(count/max(session_minutes,1),1)
| where polls_per_minute >= 4
| eval risk_score=case(polls_per_minute >= 10, 80, polls_per_minute >= 4, 65, 1=1, 40)
| where risk_score >= 65
| table firstTime lastTime src app user dest_host session_minutes count polls_per_minute risk_score
```

> This search targets the Antino-specific 10-second polling interval (6 polls/minute) against graph.microsoft.com from non-standard applications. High false-positive risk — requires app field normalization in Network_Traffic data model.

### IOC-Based: Antino Staging Domain (CloudFront)

```spl
`sysmon` EventCode=22
QueryName="d32tpl7xt7175h.cloudfront.net"
| stats count min(_time) as firstTime max(_time) as lastTime by host user QueryName
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=90
| table firstTime lastTime host user QueryName risk_score
```

## Risk Score Logic

| Component | Score | Rationale |
|-----------|-------|-----------|
| Count 5–19 connections by non-email process | 55 | Anomalous but could be a LOB app |
| Count 20–99 connections by non-email process | 70 | High — repeated programmatic Graph API access |
| Count 100+ connections by non-email process | 85 | Critical — consistent with 10s polling interval over hours |
| Polling rate >= 4/min from non-standard app | 65 | Matches Antino C2 heartbeat pattern |
| Staging domain match (d32tpl7xt7175h) | 90 | Direct IOC match; near-certain compromise |

## Associated Threat Actors

| Actor | Malware/Tool | Reference |
|-------|-------------|-----------|
| UAT-11587 (China-nexus) | Antino Rust backdoor | [Talos Blog – UAT-11587](https://blog.talosintelligence.com/china-nexus-uat-11587-targets-government-and-policy-organizations-across-asia-with-antino-backdoor/) |
| PeckBirdy / Falcon C2 (XG) operators | Falcon C2, Antino delivery | [Unit 42 – Falcon C2](https://unit42.paloaltonetworks.com/falcon-c2-browser-compromise/) |

## References

- [Cisco Talos: UAT-11587 Antino Backdoor](https://blog.talosintelligence.com/china-nexus-uat-11587-targets-government-and-policy-organizations-across-asia-with-antino-backdoor/)
- [Unit 42: Falcon C2 Browser Compromise](https://unit42.paloaltonetworks.com/falcon-c2-browser-compromise/)
- [MITRE ATT&CK T1102.002: Web Service Bidirectional Communication](https://attack.mitre.org/techniques/T1102/002/)
- [MITRE ATT&CK T1567.002: Exfiltration to Cloud Storage](https://attack.mitre.org/techniques/T1567/002/)
