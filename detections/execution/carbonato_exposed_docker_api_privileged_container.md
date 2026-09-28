# CARBONATO: Exposed Docker Daemon API Exploitation and Privileged Container Deployment

## Description

Detects the CARBONATO botnet's initial access and execution technique: scanning for and exploiting Docker daemons with the API exposed unauthenticated on TCP port 2375, then launching a privileged container (`--privileged`) to escape to the host. CARBONATO also deploys Hermes Agent (reprogrammed as "GH0ST") for Telegram-controlled AI-agent-based post-exploitation.

This is a persistently misused Docker misconfiguration — exposing port 2375 without authentication grants full root-equivalent access to any reachable host. The detection covers three layers: (1) inbound network connections to port 2375 from non-internal hosts, (2) privileged container creation events in Docker daemon logs, and (3) reverse SSH tunnel creation from container processes.

False positive sources: internal Docker management tooling (e.g., CI/CD runners, Portainer, Rancher) legitimately connecting to port 2375 within the same LAN. The discriminator is source IP scope — internal management IPs should be allowlisted; any external source connecting to port 2375 is an immediate indicator.

## MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| Tactic | Execution |
| Tactic ID | TA0002 |
| Technique | Deploy Container |
| Technique ID | T1610 |

Secondary mappings:
- TA0001 / T1133 — External Remote Services (exposed Docker API as initial access vector)
- TA0003 / T1053.003 — Scheduled Task/Job: Cron (CARBONATO persistence)
- TA0003 / T1098.004 — Account Manipulation: SSH Authorized Keys (operator key installation)
- TA0008 / T1572 — Protocol Tunneling (reverse SSH tunnel C2)

## Lockheed Martin Kill Chain

| Phase |
|-------|
| Exploitation |
| Installation |

## Splunk Detection Query

### Primary: Inbound Connection to Docker Daemon API Port 2375
```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Network_Traffic.All_Traffic
  where All_Traffic.dest_port=2375
    AND All_Traffic.transport="tcp"
  by All_Traffic.src All_Traffic.src_ip All_Traffic.dest All_Traffic.dest_ip All_Traffic.dest_port
| `drop_dm_object_name(All_Traffic)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    count > 50, 95,
    count > 10, 90,
    1=1, 75)
| where risk_score >= 75
| table firstTime lastTime src src_ip dest dest_ip dest_port count risk_score
```

### Secondary: Privileged Container Creation via Docker API
```spl
index=* sourcetype IN ("docker","docker:daemon","docker:events","syslog","linux_secure")
  (uri="/containers/create" OR match(uri, "/v[0-9.]+/containers/create"))
| rex field=_raw "\"Privileged\"\s*:\s*(?P<privileged>true|false)"
| where privileged="true"
| eval risk_score=95
| table _time host src uri privileged Image risk_score
```

### Tertiary: Reverse SSH Tunnel Created from Container or Non-Interactive Shell
```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Processes
  where Processes.process_name="ssh"
    AND (Processes.process="* -R *" OR Processes.process="*-R*@*")
    AND Processes.parent_process_name IN ("sh","bash","zsh","dash","runc","containerd-shim","dockerd")
  by Processes.dest Processes.user Processes.parent_process_name
     Processes.process_name Processes.process Processes.process_id
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=90
| where risk_score >= 90
| table firstTime lastTime dest user parent_process_name process_name process risk_score
```

### Quaternary: SSH Authorized Keys File Modified by Container-Spawned Process
```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Filesystem
  where Filesystem.file_path IN ("*/.ssh/authorized_keys","*/.ssh/authorized_keys2")
    AND Filesystem.action IN ("created","modified","write")
  by Filesystem.dest Filesystem.user Filesystem.process_name Filesystem.file_path
| `drop_dm_object_name(Filesystem)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    match(file_path,"root/.ssh"), 90,
    1=1, 80)
| where risk_score >= 80
| table firstTime lastTime dest user process_name file_path risk_score
```

### Quinary: Cron or Systemd Timer Created by Unexpected Process
```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Filesystem
  where Filesystem.file_path IN ("/etc/cron.d/*","/etc/cron.daily/*","/var/spool/cron/crontabs/*",
    "/etc/systemd/system/*.timer","/etc/systemd/system/*.service")
    AND Filesystem.action="created"
    AND NOT Filesystem.process_name IN ("crontab","dpkg","rpm","apt","yum","systemd","dbus-daemon")
  by Filesystem.dest Filesystem.user Filesystem.process_name Filesystem.file_name Filesystem.file_path
| `drop_dm_object_name(Filesystem)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=75
| where risk_score >= 75
| table firstTime lastTime dest user process_name file_name file_path risk_score
```

## Risk Score Logic

| Condition | Score | Rationale |
|-----------|-------|-----------|
| Inbound TCP/2375 from external source (>50 connections) | 95 | Active exploitation or mass scanning; TCP/2375 should never receive external traffic |
| Inbound TCP/2375 from external source (>10 connections) | 90 | Targeted exploitation attempt |
| Any inbound TCP/2375 | 75 | Any external access to unauthenticated Docker API is anomalous |
| Privileged container creation via API | 95 | `--privileged` containers escape host cgroup/namespace controls; near-certain malicious if API-triggered |
| Reverse SSH tunnel from container process | 90 | Classic C2 persistence; container-spawned SSH is nearly always attacker-controlled |
| SSH authorized_keys modification at root | 90 | Operator SSH key installation for persistent backdoor access |
| Cron/systemd timer created by non-package-manager | 75 | Worm-style persistence mechanism used by CARBONATO for 5-minute scanning cycles |

## Associated Threat Actors

| Actor | References |
|-------|-----------|
| CARBONATO (Unknown financially motivated) | [ThreatDown — CARBONATO (2026-09)](https://www.threatdown.com/blog/carbonato/) |
| TeamTNT (Docker API exploitation) | [MITRE ATT&CK G0139](https://attack.mitre.org/groups/G0139/) |
| Kinsing (Docker API crypto-mining) | [Aqua Security — Kinsing Malware](https://www.aquasec.com/cloud-native-threats/kinsing-malware/) |

## References

- [ThreatDown: CARBONATO — a botnet built around an AI agent](https://www.threatdown.com/blog/carbonato/)
- [BleepingComputer: New Carbonato malware uses AI agents to hijack exposed Docker hosts](https://www.bleepingcomputer.com/news/security/new-carbonato-malware-uses-ai-agents-to-hijack-exposed-docker-hosts/)
- [MITRE ATT&CK T1610: Deploy Container](https://attack.mitre.org/techniques/T1610/)
- [MITRE ATT&CK T1133: External Remote Services](https://attack.mitre.org/techniques/T1133/)
- [Docker documentation: Protect the Docker daemon socket](https://docs.docker.com/engine/security/protect-access/)
