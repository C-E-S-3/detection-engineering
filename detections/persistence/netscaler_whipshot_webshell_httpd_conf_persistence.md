# NetScaler WHIPSHOT Web Shell Persistence via httpd.conf Modification

## Description

Detects the WHIPSHOT PHP web shell persistence mechanism used in active exploitation of Citrix NetScaler CVE-2026-88772. Attackers modify `/nsconfig/httpd.conf` on NetScaler ADC and Gateway appliances to register a PHP handler pointing to a web shell planted in VPN script directories, causing Apache httpd to execute the web shell on each matching HTTP request. This modification survives appliance reboots and credential rotation.

Also detects SLAPSHOT, the Python TCP tunneler deployed post-exploitation via WHIPSHOT. SLAPSHOT creates two artifacts on startup: `/tmp/.uxdport` (stores the listening port) and `/tmp/.uxdlock` (instance lock). Detection of these artifacts is a near-certain indicator of post-exploitation activity.

**False positives:** Essentially none. NetScaler ADC/Gateway appliances do not ship with PHP scripts in VPN directories, do not serve PHP through their embedded Apache instance in production configurations, and do not use `/tmp/.uxdport` or `/tmp/.uxdlock`. Any hit on these detections should be treated as a confirmed compromise until forensically cleared.

## MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| Tactic | Persistence |
| Tactic ID | TA0003 |
| Technique | Server Software Component: Web Shell |
| Technique ID | T1505.003 |
| Secondary Tactic | Initial Access (TA0001) — T1190 Exploit Public-Facing Application |
| Secondary Tactic | Command and Control (TA0011) — T1572 Protocol Tunneling (SLAPSHOT) |

## Lockheed Martin Kill Chain

| Phase |
|-------|
| Installation |
| Actions on Objectives |

## Splunk Detection Query

### Query 1: WHIPSHOT — PHP Web Shell Written to NetScaler Paths

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Filesystem
  where Filesystem.file_path IN ("/netscaler/ns_gui/vpn/*", "/var/netscaler/gui/vpn/*",
                                   "/netscaler/*", "/nsconfig/*")
    AND Filesystem.file_name IN ("*.php", "*.phtml", "*.php5", "*.php7", "*.phar")
    AND Filesystem.action IN ("created", "modified", "write")
  by Filesystem.dest Filesystem.user Filesystem.file_name Filesystem.file_path Filesystem.action
| `drop_dm_object_name(Filesystem)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    match(file_path, "vpn/"), 95,
    match(file_path, "/netscaler/"), 90,
    match(file_path, "/nsconfig/"), 90,
    1=1, 80)
| where risk_score >= 80
| table firstTime lastTime dest user file_name file_path action risk_score
```

### Query 2: WHIPSHOT — httpd.conf Modification on NetScaler Appliance

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Filesystem
  where Filesystem.file_path="/nsconfig/httpd.conf"
    AND Filesystem.action IN ("created", "modified", "write")
  by Filesystem.dest Filesystem.user Filesystem.file_name Filesystem.file_path Filesystem.action
| `drop_dm_object_name(Filesystem)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=95
| table firstTime lastTime dest user file_name file_path action risk_score
```

### Query 3: SLAPSHOT — Lock/Port File Artifacts in /tmp

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Filesystem
  where Filesystem.file_path IN ("/tmp/.uxdport", "/tmp/.uxdlock")
    AND Filesystem.action IN ("created", "modified", "write")
  by Filesystem.dest Filesystem.user Filesystem.file_name Filesystem.file_path Filesystem.action
| `drop_dm_object_name(Filesystem)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=98
| table firstTime lastTime dest user file_name file_path action risk_score
```

### Query 4: SLAPSHOT — Python Process Spawned by Web Server on Network Appliance

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Processes
  where Processes.process_name IN ("python", "python3", "python2")
    AND Processes.parent_process_name IN ("httpd", "apache2", "nsppe", "sh", "bash")
  by Processes.dest Processes.user Processes.parent_process_name
     Processes.process_name Processes.process Processes.process_id
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    parent_process_name IN ("httpd","apache2"), 90,
    parent_process_name="nsppe", 95,
    1=1, 75)
| where risk_score >= 75
| table firstTime lastTime dest user parent_process_name process_name process risk_score
```

## Risk Score Logic

| Condition | Score | Rationale |
|-----------|-------|-----------|
| PHP file written under VPN script directory | 95 | No legitimate operation writes PHP to NetScaler VPN paths |
| PHP file written under `/netscaler/` or `/nsconfig/` | 90 | Same — no valid production use case |
| `/nsconfig/httpd.conf` modified | 95 | Configuration file only modified during vendor-sanctioned upgrades; any other write is WHIPSHOT |
| `/tmp/.uxdport` or `/tmp/.uxdlock` created | 98 | SLAPSHOT-specific artifacts; near-certain indicator of post-exploitation |
| Python spawned from httpd/apache2 parent | 90 | Web shell command execution; httpd does not normally invoke Python |
| Python spawned from nsppe parent | 95 | Packet processing engine spawning Python is deeply anomalous |

## Associated Threat Actors

| Actor | References |
|-------|-----------|
| Unattributed (GTIG UNC cluster, as of 2026-09-29) | [Google GTIG / Mandiant — WHIPSHOT SLAPSHOT Campaign (2026-09-29)](https://cloud.google.com/blog/topics/threat-intelligence/defending-against-active-exploitation-of-citrix-netscaler-adc-and-gateway-appliances) |

## References

- [Google GTIG / Mandiant: Defending Against Active Exploitation of Citrix NetScaler ADC and Gateway Appliances (2026-09-29)](https://cloud.google.com/blog/topics/threat-intelligence/defending-against-active-exploitation-of-citrix-netscaler-adc-and-gateway-appliances)
- [CISA KEV: CVE-2026-88771 and CVE-2026-88772 (2026-09-27)](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
- [Citrix Security Bulletin CTX697096](https://support.citrix.com/external/article/CTX697096)
- [MITRE ATT&CK T1505.003 — Server Software Component: Web Shell](https://attack.mitre.org/techniques/T1505/003/)
- [MITRE ATT&CK T1572 — Protocol Tunneling](https://attack.mitre.org/techniques/T1572/)
- [MITRE ATT&CK T1190 — Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/)
