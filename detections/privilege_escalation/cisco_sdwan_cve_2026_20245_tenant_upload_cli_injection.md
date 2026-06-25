# Cisco SD-WAN CVE-2026-20245: Privilege Escalation via CLI Tenant-Upload Command Injection

## Description

Detects active exploitation of CVE-2026-20245, a CVSS 7.8 privilege escalation vulnerability in Cisco Catalyst SD-WAN Manager (vManage). An authenticated attacker with `netadmin` privileges can execute arbitrary OS commands as root by uploading a crafted CSV file via the SD-WAN CLI command `request tenant-upload tenant-list`. The internal processing script `vconfd_script_upload_tenant_list.sh` fails to sanitize file content, executing attacker-controlled shell commands.

Mandiant (Google Threat Intelligence Group) disclosed active exploitation on June 24, 2026. The observed attack chain chains two prior auth bypass CVEs to establish unauthorized SD-WAN peering (CVE-2026-20127 or CVE-2026-20182), then escalates to root via CVE-2026-20245. The attacker created a backdoor root account (`troot`, UID 0), exfiltrated SD-WAN configuration via the web interface, and performed thorough anti-forensic cleanup: deleting the exploit payload (`evil_tenant.csv`) and restoring original `/etc/passwd` and `/etc/shadow` files.

**Attack chain:**

1. Auth bypass (CVE-2026-20127/20182) → rogue SD-WAN peering established from 8 known attacker IPs
2. SSH as `admin` or `vmanage-admin` → elevated CLI access
3. CVE-2026-20245: `request tenant-upload tenant-list /home/admin/evil_tenant.csv vpn 0` → root shell via injection in `vconfd_script_upload_tenant_list.sh`
4. Inject `troot:x:0:0:root:/root:/bin/bash` into `/etc/passwd` and `/etc/shadow`
5. Exfiltrate SD-WAN config via POST to `/j_security_check`
6. Delete `evil_tenant.csv`, restore `/etc/passwd`/`/etc/shadow`, run cleanup validation script

**False positive sources:** Legitimate SD-WAN upgrades may invoke `vconfd_script_upload_tenant_list.sh`; baseline invocations during scheduled maintenance windows to suppress. The `troot` username is campaign-specific and has no legitimate use. The filename `evil_tenant.csv` is an unambiguous IOC.

**Patched versions:** 20.9.9.2, 20.12.7.2, 20.15.4.5, 20.15.5.3, 20.18.3.1, 26.1.1.2+

## MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| Tactic | Privilege Escalation |
| Tactic ID | TA0004 |
| Technique | Exploitation for Privilege Escalation |
| Technique ID | T1068 |

Secondary techniques:
- T1190 (Initial Access: Exploit Public-Facing Application — CVE-2026-20127/20182 auth bypass)
- T1136 (Persistence: Create Account — troot UID 0 backdoor account)
- T1078 (Persistence/Initial Access: Valid Accounts — SSH as vmanage-admin, su to troot)
- T1005 (Collection: Data from Local System — SD-WAN config exfiltration)
- T1070 (Defense Evasion: Indicator Removal — passwd/shadow restoration)
- T1070.004 (Defense Evasion: Indicator Removal: File Deletion — evil_tenant.csv deletion)

## Lockheed Martin Kill Chain

| Phase |
|-------|
| Exploitation |
| Installation |
| Actions on Objectives |

## Known IOCs

| Type | Value | Description |
|------|-------|-------------|
| IP | `126.51.108.152` | Rogue SD-WAN peering device (Mandiant, June 2026) |
| IP | `76.92.245.217` | Rogue SD-WAN peering device |
| IP | `207.190.37.94` | Rogue SD-WAN peering device |
| IP | `23.245.7.178` | Rogue SD-WAN peering device |
| IP | `153.186.231.233` | Rogue SD-WAN peering device |
| IP | `167.179.79.189` | Rogue SD-WAN peering device |
| IP | `45.32.38.160` | Rogue SD-WAN peering device |
| IP | `209.137.225.101` | Rogue SD-WAN peering device |
| SHA256 | `b82936f37648518425c7d3cf9e09eaffa41d7cdb3840f6a40287e3a108880f7b` | evil_tenant.csv — CLI injection payload |
| Username | `troot` | Backdoor root account (UID 0) injected into /etc/passwd |

## Wazuh Detection Rules

Rules 103660–103671 in `wazuh/rules/threat-intel-2026-06-25-cisco-sdwan-cve-2026-20245.xml`:

| Rule ID | Level | Description |
|---------|-------|-------------|
| 103660 | 14 | Suricata: alert from rogue SD-WAN IOC IP (src) |
| 103661 | 12 | Suricata: alert to rogue SD-WAN IOC IP (dst) |
| 103662 | 15 | SSH auth from rogue SD-WAN IOC IP (CRITICAL) |
| 103663 | 12 | SSH login as vmanage-admin or admin |
| 103664 | 14 | Auditd: tenant-upload CLI command executed |
| 103665 | 13 | Syslog: vconfd_script_upload_tenant_list spawned |
| 103666 | 15 | FIM: evil_tenant.csv payload detected (CRITICAL) |
| 103667 | 15 | Any syslog event containing `troot` (CRITICAL) |
| 103668 | 13 | Auditd: /etc/passwd or /etc/shadow written by unexpected process |
| 103669 | 13 | Auditd: exploit artifact file deleted (anti-forensic cleanup) |
| 103670 | 12 | Syslog: SD-WAN tenant validation/cleanup script activity |
| 103671 | 15 | Correlation: CLI injection → passwd modification within 10 min (CRITICAL) |

## Splunk Detection Query

**Network IOC: Traffic from/to known rogue SD-WAN peering device IPs**

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Network_Traffic.All_Traffic
  where (All_Traffic.src_ip IN ("126.51.108.152","76.92.245.217","207.190.37.94","23.245.7.178",
         "153.186.231.233","167.179.79.189","45.32.38.160","209.137.225.101")
    OR All_Traffic.dest_ip IN ("126.51.108.152","76.92.245.217","207.190.37.94","23.245.7.178",
         "153.186.231.233","167.179.79.189","45.32.38.160","209.137.225.101"))
  by All_Traffic.src_ip All_Traffic.dest_ip All_Traffic.dest_port All_Traffic.transport
| `drop_dm_object_name(All_Traffic)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=90
| table firstTime lastTime src_ip dest_ip dest_port transport count risk_score
```

**Exploitation: SD-WAN CLI tenant-upload command in process execution**

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Processes
  where Processes.process LIKE "%tenant-upload%" OR Processes.process LIKE "%tenant-list%"
    OR Processes.process LIKE "%vconfd_script_upload_tenant_list%"
  by Processes.dest Processes.user Processes.parent_process_name
     Processes.process_name Processes.process Processes.process_id
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=95
| where risk_score >= 95
| table firstTime lastTime dest user parent_process_name process_name process risk_score
```

**Exploit payload: evil_tenant.csv file IOC on SD-WAN appliances**

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Filesystem
  where Filesystem.file_name="evil_tenant.csv"
    OR Filesystem.file_path IN ("*/home/admin/.orig_passwd","*/home/admin/.orig_shadow")
    OR Filesystem.file_hash="b82936f37648518425c7d3cf9e09eaffa41d7cdb3840f6a40287e3a108880f7b"
  by Filesystem.dest Filesystem.user Filesystem.file_path Filesystem.file_name Filesystem.process_name
| `drop_dm_object_name(Filesystem)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=95
| table firstTime lastTime dest user file_path file_name process_name risk_score
```

**Persistence: troot backdoor account in authentication logs**

```spl
index=* (source="/var/log/auth.log" OR source="*auth.log*" OR source="/var/log/secure")
("troot" OR "su - troot" OR "su troot")
| rex field=_raw "from (?P<src_ip>[\d\.]+) port (?P<src_port>\d+)"
| stats count min(_time) as firstTime max(_time) as lastTime values(src_ip) as source_ips by host
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=95
| table firstTime lastTime host source_ips count risk_score
```

**Defense Evasion: /etc/passwd modification followed by rapid deletion (cleanup)**

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Filesystem
  where (Filesystem.file_path="/etc/passwd" OR Filesystem.file_path="/etc/shadow")
    AND Filesystem.action IN ("modified","deleted")
  by Filesystem.dest Filesystem.user Filesystem.file_path Filesystem.action Filesystem.process_name
| `drop_dm_object_name(Filesystem)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(action="deleted", 85, action="modified", 75, 1=1, 50)
| where risk_score >= 75
| table firstTime lastTime dest user file_path action process_name risk_score
```

## Risk Score Logic

| Condition | Score | Rationale |
|-----------|-------|-----------|
| `troot` username in any auth/syslog event | 95 | Campaign-specific IOC with no legitimate use |
| evil_tenant.csv present on filesystem | 95 | Exploit payload; unambiguous IOC |
| Traffic to/from rogue SD-WAN IOC IPs | 90 | Mandiant-attributed attacker infrastructure |
| SSH auth from rogue IOC IP | 90 | Successful access from confirmed attacker IP |
| tenant-upload CLI command executed | 85 | CVE-2026-20245 direct exploitation pathway |
| /etc/passwd modified by non-standard process | 75 | Root backdoor injection pattern |
| SSH login as vmanage-admin or admin | 60 | Privileged SD-WAN account — correlate with other indicators |

## Associated Threat Actors

| Actor | References |
|-------|-----------|
| Unattributed (state-sponsored suspected, Mandiant) | [Mandiant GTIG Blog](https://cloud.google.com/blog/topics/threat-intelligence/zero-day-exploitation-cisco-catalyst-sd-wan-manager) |

Prior related campaigns on Cisco SD-WAN Manager:
- UAT-8616 (CVE-2026-20182 auth bypass exploitation, May 2026)

## References

- [Mandiant/GTIG: Zero-Day Exploitation of CVE-2026-20245 in Cisco Catalyst SD-WAN Manager (2026-06-24)](https://cloud.google.com/blog/topics/threat-intelligence/zero-day-exploitation-cisco-catalyst-sd-wan-manager)
- [Cisco Security Advisory CVE-2026-20245](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-privesc-4uxFrdzx)
- [Cisco Security Advisory CVE-2026-20127](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-rpa-EHchtZk)
- [Cisco Security Advisory CVE-2026-20182](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-rpa2-v69WY2SW)
- [MITRE ATT&CK T1068 - Exploitation for Privilege Escalation](https://attack.mitre.org/techniques/T1068/)
- [MITRE ATT&CK T1136 - Create Account](https://attack.mitre.org/techniques/T1136/)
- [MITRE ATT&CK T1190 - Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/)
