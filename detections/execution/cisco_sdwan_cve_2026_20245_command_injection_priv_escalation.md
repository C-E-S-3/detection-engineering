# Cisco SD-WAN Manager CLI Command Injection Privilege Escalation (CVE-2026-20245)

## Description

Detects exploitation of CVE-2026-20245, a command injection zero-day in the Cisco Catalyst SD-WAN Manager CLI disclosed June 5, 2026. An authenticated user with netadmin privileges uploads a crafted file to trigger OS command injection that executes as root. The vulnerability stems from insufficient validation of user-supplied input in the `vconfd_script_upload_tenant_list.sh` upload handler. No patch or workaround exists at disclosure.

This detection is particularly important because CVE-2026-20245 is a natural escalation path from CVE-2026-20182 (CVSS 10.0 authentication bypass, CISA KEV May 2026) — an attacker who exploited CVE-2026-20182 to obtain netadmin credentials can chain directly to root via CVE-2026-20245. Root access to the SD-WAN Manager controller enables configuration pushes to all managed edge devices.

False positives: legitimate SD-WAN Manager maintenance tasks may generate entries in scripts.log; establish a baseline of expected `vconfd_script_upload_tenant_list.sh` invocations from authorized management hosts.

## MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| Tactic | Execution |
| Tactic ID | TA0002 |
| Technique | Command and Scripting Interpreter: Unix Shell |
| Technique ID | T1059.004 |

Secondary: T1068 (Exploitation for Privilege Escalation — netadmin → root), T1210 (Exploitation of Remote Services — configuration push to edge devices post-compromise)

## Lockheed Martin Kill Chain

| Phase |
|-------|
| Exploitation |

## Splunk Detection Query

```spl
`-- Primary: detect suspicious vconfd_script_upload invocations in SD-WAN scripts.log`
index=* (source="*scripts.log*" OR source="*/var/log/scripts.log")
"vconfd_script_upload_tenant_list.sh"
| rex field=_raw "vconfd_script_upload_tenant_list\.sh\s+(?P<upload_path>\S+)"
| eval risk_score=case(
    match(upload_path, "^/var/tmp/|^/tmp/|^/home/|^/opt/"), 95,
    match(upload_path, "\.\."), 95,
    isnull(upload_path), 80,
    1=1, 80)
| where risk_score >= 80
| stats count min(_time) as firstTime max(_time) as lastTime values(upload_path) as upload_paths
    by host
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| table firstTime lastTime host upload_paths count risk_score
```

```spl
`-- Supplemental: detect unexpected child processes spawned by SD-WAN vManage service processes`
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Processes
  where Processes.parent_process_name IN ("vconfd","vmanage-server","vmanage","nms")
    AND Processes.process_name IN ("sh","bash","curl","wget","python3","nc","ncat",
                                    "id","whoami","chmod","ssh-keygen","sed","awk")
  by Processes.dest Processes.user Processes.parent_process_name Processes.process_name
     Processes.process Processes.process_id
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    process_name IN ("nc","ncat","ssh-keygen"), 95,
    process_name IN ("curl","wget","bash","sh"), 85,
    1=1, 75)
| where risk_score >= 75
| table firstTime lastTime dest user parent_process_name process_name process risk_score
```

```spl
`-- Supplemental: detect file writes to SD-WAN temp directories by vManage processes`
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Filesystem
  where Filesystem.file_path IN ("*/var/tmp/*","*/tmp/*")
    AND Filesystem.action IN ("created","write","modified")
    AND (Filesystem.process_name IN ("vconfd","vmanage-server","nms")
         OR Filesystem.file_name IN ("*.sh","*.py","*.elf","*.bin"))
  by Filesystem.dest Filesystem.user Filesystem.file_path Filesystem.file_name
     Filesystem.process_name
| `drop_dm_object_name(Filesystem)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    match(file_name,"\.sh$|\.py$|\.elf$|\.bin$"), 90,
    1=1, 75)
| where risk_score >= 75
| table firstTime lastTime dest user file_path file_name process_name risk_score
```

## Risk Score Logic

| Condition | Score | Rationale |
|-----------|-------|-----------|
| `vconfd_script_upload_tenant_list.sh` called with /var/tmp/, /tmp/, or /home/ path | 95 | Strongly indicates exploitation via crafted file upload to writable attacker-controlled path |
| `vconfd_script_upload_tenant_list.sh` with `..` path traversal in argument | 95 | Path traversal in upload argument is direct evidence of CVE-2026-20245 exploitation attempt |
| `vconfd_script_upload_tenant_list.sh` invoked with no recognizable argument (parse failure) | 80 | Anomalous invocation pattern; baseline normal invocations from authorized management workflows |
| SD-WAN service process spawning shell (bash/sh) | 85 | SD-WAN services should not spawn interactive shells; indicates OS command injection |
| SD-WAN service process spawning curl/wget | 85 | Payload download indication; post-exploitation C2 staging |
| SD-WAN service process spawning nc/ncat/ssh-keygen | 95 | Reverse shell or SSH key injection for persistent backdoor access |
| ELF/shell script written to /tmp or /var/tmp by SD-WAN process | 90 | Attacker staging exploit or backdoor payload on the management node |

## Associated Threat Actors

| Actor | References |
|-------|-----------|
| Unknown (active exploitation, June 2026) | [Cisco Security Advisory cisco-sa-sdwan-privesc-4uxFrdzx](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-privesc-4uxFrdzx) |
| UAT-8616 (likely chaining from CVE-2026-20182) | [Cisco Talos — UAT-8616 SD-WAN Active Exploitation](https://blog.talosintelligence.com/uat-8616-sd-wan/), [MITRE ATT&CK G1061](https://attack.mitre.org/groups/G1061/) |

## References

- [Cisco Security Advisory cisco-sa-sdwan-privesc-4uxFrdzx (CVE-2026-20245)](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-privesc-4uxFrdzx)
- [Help Net Security — CVE-2026-20245 0-day Exploited (2026-06-05)](https://www.helpnetsecurity.com/2026/06/05/cisco-sd-wan-cve-2026-20245-0-day-exploited/)
- [SecurityWeek — 7th Cisco SD-WAN Zero-Day Exploited in 2026](https://www.securityweek.com/cisco-warns-of-7th-sd-wan-zero-day-exploited-in-2026/)
- [MITRE ATT&CK — T1059.004 Unix Shell](https://attack.mitre.org/techniques/T1059/004/)
- [MITRE ATT&CK — T1068 Exploitation for Privilege Escalation](https://attack.mitre.org/techniques/T1068/)
