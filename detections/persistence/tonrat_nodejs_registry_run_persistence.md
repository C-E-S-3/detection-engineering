# TonRAT Node.js Registry Run Key Persistence

## Description

Detects the persistence mechanism used by TonRAT, a Node.js-based JavaScript implant deployed against hospitality sector organizations in Europe and Asia (Microsoft Threat Intelligence, June 2026). TonRAT installs an embedded Node.js v24.13.0 runtime (node.exe, ~89.9 MB) to a non-standard path under ProgramData or AppData, then establishes dual registry persistence: a Run key pointing to the Node.js implant, and a self-refreshing RunOnce key that re-registers itself after each execution. This self-refreshing RunOnce mechanism creates resilience against single-path remediation.

Node.js (node.exe) is a legitimate runtime environment, but it has no business reason to appear in registry Run/RunOnce keys under user-writable paths such as ProgramData. False positives from legitimate Node.js installations in standard Program Files paths should be investigated and documented.

Secondary detection covers the execution chain: PowerShell spawning node.exe from non-standard directories, or node.exe making outbound connections on non-standard high ports (56001/56002/56003).

## MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| Tactic | Persistence |
| Tactic ID | TA0003 |
| Technique | Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder |
| Technique ID | T1547.001 |
| Sub-technique note | Dual Run + self-refreshing RunOnce persistence for operational resilience |

| Field | Value |
|-------|-------|
| Tactic | Execution |
| Tactic ID | TA0002 |
| Technique | Command and Scripting Interpreter: JavaScript |
| Technique ID | T1059.007 |
| Sub-technique note | JavaScript implant executed by embedded Node.js runtime deployed to ProgramData |

| Field | Value |
|-------|-------|
| Tactic | Command and Control |
| Tactic ID | TA0011 |
| Technique | Non-Standard Port |
| Technique ID | T1571 |
| Sub-technique note | C2 on ports 56001/56002/56003/8443/8445/8453/5555 |

## Lockheed Martin Kill Chain

| Phase |
|-------|
| Installation |
| Command & Control (C2) |

## Splunk Detection Query

Registry Run key persistence for Node.js in non-standard paths:

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Endpoint.Registry
where (Registry.registry_key_name="*\\CurrentVersion\\Run"
       OR Registry.registry_key_name="*\\CurrentVersion\\RunOnce")
  AND (Registry.registry_value_data="*node.exe*"
       OR Registry.registry_value_data="*node *")
by Registry.dest Registry.user Registry.registry_key_name
   Registry.registry_value_name Registry.registry_value_data
| `drop_dm_object_name(Registry)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    match(registry_value_data, "(?i)(programdata|appdata|temp|tmp|public|users\\\\[^\\\\]+\\\\appdata)"), 90,
    match(registry_key_name, "(?i)runonce"), 80,
    1=1, 65)
| where risk_score >= 65
| table firstTime lastTime dest user registry_key_name registry_value_name registry_value_data risk_score
```

Node.js execution from non-standard path spawned by scripting interpreters:

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Endpoint.Processes
where Processes.process_name="node.exe"
  AND (Processes.process="*ProgramData*"
       OR Processes.process="*AppData\\Local\\Temp*"
       OR Processes.process="*AppData\\Roaming*"
       OR Processes.process="*\\Users\\Public\\*")
by Processes.dest Processes.user Processes.parent_process_name
   Processes.process_name Processes.process Processes.process_id
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    match(parent_process_name, "(?i)powershell|cmd|wscript|mshta|cscript|rundll32"), 90,
    match(parent_process_name, "(?i)svchost|services"), 75,
    1=1, 60)
| where risk_score >= 60
| table firstTime lastTime dest user parent_process_name process_name process risk_score
```

Non-standard port C2 from node.exe (TonRAT C2 beacon):

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Network_Traffic.All_Traffic
where All_Traffic.process_name="node.exe"
  AND All_Traffic.dest_port IN (56001, 56002, 56003, 8443, 8445, 8453, 5555)
  AND All_Traffic.dest_ip NOT IN ("127.0.0.1","::1","0.0.0.0")
by All_Traffic.src All_Traffic.dest All_Traffic.dest_ip All_Traffic.dest_port All_Traffic.process_name
| `drop_dm_object_name(All_Traffic)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    dest_port IN (56001, 56002, 56003), 90,
    1=1, 75)
| where risk_score >= 75
| table firstTime lastTime src dest dest_ip dest_port process_name risk_score
```

## Risk Score Logic

| Condition | Score | Rationale |
|-----------|-------|-----------|
| node.exe in Run/RunOnce key pointing to ProgramData or AppData path | 90 | Node.js has no legitimate reason in these registry keys from user-writable paths |
| node.exe in RunOnce key (any path) | 80 | Self-refreshing RunOnce is the specific TonRAT resilience mechanism |
| node.exe in Run/RunOnce key (non-ProgramFiles path) | 65 | Anomalous — investigate path and parent installer |
| node.exe spawned from PowerShell/cmd/mshta in non-standard directory | 90 | Execution chain matches TonRAT delivery pattern |
| node.exe making outbound connections on ports 56001/56002/56003 | 90 | Campaign-specific non-standard ports; no legitimate Node.js application uses these |

## Associated Threat Actors

| Actor | References |
|-------|-----------|
| Unknown (unattributed as of June 2026) | [Microsoft TI — Photo ZIP Campaign (2026-06-25)](https://www.microsoft.com/en-us/security/blog/2026/06/25/photo-zip-campaign-targeting-hospitality-industry-delivers-node-js-implant-persistent-access/) |

## References

- [Microsoft Threat Intelligence — Photo ZIP Campaign Targeting Hospitality (2026-06-25)](https://www.microsoft.com/en-us/security/blog/2026/06/25/photo-zip-campaign-targeting-hospitality-industry-delivers-node-js-implant-persistent-access/)
- [MITRE ATT&CK — T1547.001 Boot or Logon Autostart Execution: Registry Run Keys](https://attack.mitre.org/techniques/T1547/001/)
- [MITRE ATT&CK — T1059.007 Command and Scripting Interpreter: JavaScript](https://attack.mitre.org/techniques/T1059/007/)
- [MITRE ATT&CK — T1571 Non-Standard Port](https://attack.mitre.org/techniques/T1571/)
