---
scraped_at: 2026-09-28T08:00:00Z
source_url: https://www.threatdown.com/blog/carbonato/
report_type: threat-intel
severity: high
title: "CARBONATO: AI-Orchestrated Docker Botnet Using Hermes Agent Framework via Exposed Daemon Port 2375"
---

# CARBONATO: AI-Orchestrated Docker Botnet Using Hermes Agent Framework via Exposed Daemon Port 2375

## 1. IOCs

### Domains / Infrastructure
| Indicator | Type | Context |
|-----------|------|---------|
| `api.telegram.org` | Abused Legitimate Service | Telegram Bot API used as C2 channel for operator commands and deployment notifications |

### Docker Registry / Container Images
A publicly exposed Docker registry (taken down after discovery) contained 59 repositories, 234 image tags, and 605 blobs (4.3 GB total) spanning October 2024 through August 2026. Specific image names are not published, but the registry documented two capability lines:
- A **factory**: distributing trojanized cryptocurrency wallet applications
- A **botnet component**: containerized tooling for Docker daemon exploitation and Hermes Agent deployment

No public registry URL or specific image SHA256 digests have been released.

### File Artifacts
| Artifact | Context |
|----------|---------|
| `SOUL.md` | Hermes Agent persona file; overwritten by attackers with "GH0ST" identity/instructions to repurpose the AI agent framework |

## 2. TTPs

| Tactic | Technique ID | Technique | Usage |
|--------|-------------|-----------|-------|
| Reconnaissance | TA0043 | T1595.002 | Active Scanning: Vulnerability Scanning — continuous scanning for exposed Docker API port 2375, every 5 minutes |
| Initial Access | TA0001 | T1133 | External Remote Services — unauthenticated Docker daemon API on TCP/2375 accessed directly without credentials |
| Execution | TA0002 | T1610 | Deploy Container — privileged container (`--privileged`) deployed via Docker API to gain host-level access |
| Execution | TA0002 | T1059.004 | Command and Scripting Interpreter: Unix Shell — shell commands delivered via Telegram to Hermes Agent |
| Persistence | TA0003 | T1053.003 | Scheduled Task/Job: Cron — cron jobs installed for persistence and scanning |
| Persistence | TA0003 | T1543.002 | Create or Modify System Process: Systemd Service — systemd timers for persistent execution |
| Persistence | TA0003 | T1098.004 | Account Manipulation: SSH Authorized Keys — operator SSH public key added to `~/.ssh/authorized_keys` |
| Persistence | TA0003 | T1572 | Protocol Tunneling — reverse SSH tunnel established to attacker-controlled server |
| Credential Access | TA0006 | T1552.001 | Unsecured Credentials: Credentials In Files — harvests AI API keys (OpenAI, Anthropic etc.), SSH keys, AWS access tokens |
| Lateral Movement | TA0008 | T1021.004 | Remote Services: SSH — operator SSH key enables persistent lateral access to compromised hosts |
| Command and Control | TA0011 | T1102 | Web Service — Telegram Bot API used for bidirectional C2 and deployment notifications |
| Command and Control | TA0011 | T1572 | Protocol Tunneling — reverse SSH tunnel as backup C2 channel |

## 3. Malware & Tools

**CARBONATO Botnet**
- **Type:** Docker-targeting botnet with AI agent command execution
- **Discovery:** ThreatDown (Malwarebytes) research published September 2026; evidence spans October 2024 – August 2026
- **Core component:** Hermes Agent — an MIT-licensed open-source AI agent framework repurposed for malicious orchestration
  - Agent identity overwritten to "GH0ST" via modified `SOUL.md` persona file
  - Enables natural-language task execution on compromised hosts via Telegram
  - Capabilities include: running shell commands, collecting credentials, exfiltrating data, reporting results
- **Propagation:** Worm-like self-propagation; scans for new Docker API targets every 5 minutes
- **Persistence stack:** Cron + systemd timers + operator SSH key + reverse SSH tunnel (four independent persistence mechanisms)
- **Linked campaign:** The same operator infrastructure also distributes trojanized cryptocurrency wallet applications via Docker images, suggesting overlap with cryptoasset-focused threat actors

## 4. Threat Actor / Campaign Attribution

Unattributed financially motivated threat actor. Active since at least October 2024. The exposed Docker registry was discovered in August 2026. The combination of crypto wallet trojanization and cloud credential harvesting is consistent with cryptojacking and theft-focused actors.

## 5. Splunk Detection Searches

### Detect Unauthenticated Connections to Docker Daemon Port 2375
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
    count > 10, 90,
    1=1, 75)
| where risk_score >= 75
| table firstTime lastTime src src_ip dest dest_ip dest_port count risk_score
```

### Detect Privileged Container Launch via Docker API
```spl
index=* sourcetype IN ("docker","docker:events","syslog")
  ("POST /containers/create" OR "POST /v*/containers/create")
  ("--privileged" OR "\"Privileged\":true" OR "Privileged:true")
| eval risk_score=95
| table _time host src uri HostConfig.Privileged Image risk_score
```

### Detect Reverse SSH Tunnels from Container Processes
```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Processes
  where Processes.process_name="ssh"
    AND (Processes.process="*-R *" OR Processes.process="*-w *" OR Processes.process="*-L *")
    AND Processes.parent_process_name IN ("sh","bash","zsh","dash","containerd","dockerd","runc")
  by Processes.dest Processes.user Processes.parent_process_name
     Processes.process_name Processes.process Processes.process_id
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    match(process,"-R "), 90,
    1=1, 75)
| where risk_score >= 75
| table firstTime lastTime dest user parent_process_name process_name process risk_score
```

### Detect Cron or Systemd Timer Modification from Container Context
```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Filesystem
  where Filesystem.file_path IN ("/etc/cron*","/var/spool/cron/*","/etc/systemd/system/*")
    AND Filesystem.action="created"
    AND Filesystem.user NOT IN ("root")
  by Filesystem.dest Filesystem.user Filesystem.process_name Filesystem.file_name Filesystem.file_path
| `drop_dm_object_name(Filesystem)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    match(file_path,"cron"), 80,
    match(file_path,"systemd"), 70,
    1=1, 65)
| where risk_score >= 65
| table firstTime lastTime dest user process_name file_name file_path risk_score
```

### Detect SSH Authorized Keys Modification
```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Filesystem
  where Filesystem.file_path IN ("*/.ssh/authorized_keys","*/authorized_keys2")
    AND Filesystem.action IN ("created","modified","write")
  by Filesystem.dest Filesystem.user Filesystem.process_name Filesystem.file_path
| `drop_dm_object_name(Filesystem)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    user!="root", 85,
    1=1, 75)
| where risk_score >= 75
| table firstTime lastTime dest user process_name file_path risk_score
```

## 6. Executive Summary

ThreatDown (Malwarebytes) published research in September 2026 on CARBONATO, a Docker botnet with a novel architectural feature: it deploys Hermes Agent, an open-source AI agent framework, and reprograms its persona file (`SOUL.md`) to create a Telegram-controlled AI agent named "GH0ST" running inside compromised hosts. The botnet targets Docker daemons exposed on port 2375 without authentication — a common misconfiguration in cloud and home-lab environments — launches a `--privileged` container to escape to the host, installs four independent persistence mechanisms (cron, systemd, reverse SSH tunnel, operator SSH key), and scans for new victims every 5 minutes. The operator communicates via Telegram. The same infrastructure distributes trojanized cryptocurrency wallet applications, linking CARBONATO to financially motivated threat actors. Organizations should immediately audit for Docker API port 2375 exposure. The key detection is network traffic to port 2375 from external IPs, combined with privileged container creation events.

## References

- [ThreatDown: CARBONATO — a botnet built around an AI agent](https://www.threatdown.com/blog/carbonato/)
- [BleepingComputer: New Carbonato malware uses AI agents to hijack exposed Docker hosts](https://www.bleepingcomputer.com/news/security/new-carbonato-malware-uses-ai-agents-to-hijack-exposed-docker-hosts/)
- [MITRE ATT&CK T1610: Deploy Container](https://attack.mitre.org/techniques/T1610/)
- [MITRE ATT&CK T1133: External Remote Services](https://attack.mitre.org/techniques/T1133/)
- [Docker security: protect the Docker daemon socket](https://docs.docker.com/engine/security/protect-access/)
