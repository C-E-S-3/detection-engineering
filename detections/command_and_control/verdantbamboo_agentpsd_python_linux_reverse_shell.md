# VerdantBamboo AgentPSD: Python Reverse Shell C2 on Linux Servers

## Description

Detects execution of Python processes on Linux systems in contexts that suggest a reverse shell — specifically when Python is spawned from web server processes, service daemons, or other unusual parents that would not normally invoke a Python interpreter. This pattern is consistent with **AgentPSD**, a Python-based reverse shell utility deployed by VerdantBamboo (UNC5221/WARP PANDA) as a fallback persistence mechanism after primary implant removal.

AgentPSD is deployed on Linux servers in the victim environment after the threat actor pivots from an edge-appliance BRICKSTORM foothold. It connects outbound to an attacker-controlled TCP listener and provides interactive command execution. Because AgentPSD is pure Python, it leaves no compiled binary signature — detection depends on process lineage and behavioral anomalies.

**False positive sources:**
- Automated Python scripts invoked by cron or systemd for legitimate operations — tune by reviewing the specific process command line
- Ansible/Puppet/Salt management agents that run Python for configuration management tasks
- Python-based monitoring agents (Datadog, Dynatrace, New Relic) that spawn from service managers
- Development environments where Python processes are expected under many parents

## MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| Tactic | Command and Control |
| Tactic ID | TA0011 |
| Technique | Non-Application Layer Protocol |
| Technique ID | T1095 |
| Secondary Tactic | Execution |
| Secondary Tactic ID | TA0002 |
| Secondary Technique | Command and Scripting Interpreter: Python |
| Secondary Technique ID | T1059.006 |

## Lockheed Martin Kill Chain

| Phase |
|-------|
| Command & Control (C2) |

## Splunk Detection Query

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Processes
  where Processes.process_name IN ("python", "python3", "python2", "python2.7", "python3.8", "python3.9", "python3.10", "python3.11", "python3.12")
    AND NOT Processes.parent_process_name IN
      ("bash", "sh", "dash", "zsh", "ksh", "tcsh",
       "sshd", "cron", "crond", "atd",
       "systemd", "init", "upstart",
       "ansible", "ansible-playbook",
       "puppet", "puppet-agent",
       "chef-client",
       "salt-minion", "salt-call",
       "supervisord", "circusd", "gunicorn", "uwsgi", "celery",
       "jenkins", "gitlab-runner", "github-actions-runner",
       "python", "python3", "python2",
       "conda", "pipenv", "poetry")
  by Processes.dest Processes.user Processes.parent_process_name Processes.process_name
     Processes.process Processes.process_id
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    parent_process_name IN ("apache2", "nginx", "httpd", "lighttpd", "w3wp.exe", "php", "php-fpm", "php-fpm7", "php-fpm8"), 95,
    parent_process_name IN ("java", "java8", "java11", "node", "nodejs", "ruby", "perl"), 85,
    match(process, "(?i)(socket\.connect|socket\.bind|os\.system|subprocess\.Popen|exec\()"), 92,
    match(process, "(?i)(-c\s*['\"]import\s+socket|pty\.spawn|os\.dup2)"), 95,
    parent_process_name IN ("mysqld", "postgres", "mongod", "redis-server"), 80,
    user IN ("www-data", "apache", "nginx", "http", "nobody"), 85,
    1=1, 60)
| where risk_score >= 60
| table firstTime lastTime dest user parent_process_name process_name process process_id risk_score
```

## Risk Score Logic

| Condition | Score | Rationale |
|-----------|-------|-----------|
| Python spawned from web server process (apache2, nginx, w3wp, php-fpm) | 95 | Web server spawning Python is a near-certain indicator of web shell or post-exploit reverse shell; very rare in legitimate configurations |
| Python command line contains socket.connect, os.dup2, or pty.spawn | 92–95 | These Python standard library calls are the building blocks of reverse shells; legitimate scripts use them rarely if ever in a server context |
| Python spawned from database, middleware, or runtime process | 80–85 | Less common but still suspicious — legitimate orchestration typically uses dedicated agent processes |
| Python running as web server account (www-data, apache, nginx, nobody) | 85 | Process user identity confirms server-context execution, elevating reverse shell likelihood |
| Python spawned from any non-allowlisted parent | 60 | Baseline alert for analyst triage; may be legitimate but warrants investigation |

## Associated Threat Actors

| Actor | References |
|-------|-----------|
| VerdantBamboo (UNC5221 / WARP PANDA) | [Volexity — VerdantBamboo (2026-06-04)](https://www.volexity.com/blog/2026/06/04/verdantbamboo-just-another-brickstorm-in-the-firewall/), [MITRE ATT&CK G1027 — UNC5221](https://attack.mitre.org/groups/G1027/) |

## References

- [Volexity — VerdantBamboo: Just Another BRICKSTORM in the Firewall (2026-06-04)](https://www.volexity.com/blog/2026/06/04/verdantbamboo-just-another-brickstorm-in-the-firewall/)
- [BleepingComputer — Chinese APT deploys new malware to keep access to hacked networks (2026-06-05)](https://www.bleepingcomputer.com/news/security/chinese-apt-deploys-new-malware-to-keep-access-to-hacked-networks/)
- [MITRE ATT&CK — T1059.006: Python](https://attack.mitre.org/techniques/T1059/006/)
- [MITRE ATT&CK — T1095: Non-Application Layer Protocol](https://attack.mitre.org/techniques/T1095/)
