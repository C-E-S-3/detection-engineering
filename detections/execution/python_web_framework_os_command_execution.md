# Python Web Framework OS Command Execution (Langflow / Jupyter / FastAPI RCE)

## Description

Detects Python web application server processes (Langflow, gunicorn, uvicorn, Jupyter) spawning OS shell interpreters as child processes. This pattern indicates remote code execution through a Python-based web framework's API — most commonly via missing authentication on code-execution endpoints (e.g., CVE-2025-3248 in Langflow's `/api/v1/validate/code`) or similar vulnerabilities in AI pipeline frameworks, Jupyter notebooks, or FastAPI/Flask applications.

Legitimate Python web servers do not spawn interactive shells (`sh`, `bash`, `cmd.exe`, `powershell.exe`) as children under normal operation. Any occurrence warrants immediate investigation as potential exploitation.

False positives may occur if an application deliberately forks shell processes for administrative functions (e.g., a self-hosted CI/CD runner or code sandbox). Tune by suppressing known parent process paths or command-line arguments specific to legitimate use cases in the environment.

## MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| Tactic | Execution |
| Tactic ID | TA0002 |
| Technique | Command and Scripting Interpreter: Python |
| Technique ID | T1059.006 |
| Secondary Tactic | Initial Access |
| Secondary Tactic ID | TA0001 |
| Secondary Technique | Exploit Public-Facing Application |
| Secondary Technique ID | T1190 |

## Lockheed Martin Kill Chain

| Phase |
|-------|
| Exploitation |

## Splunk Detection Query

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Processes
  where Processes.parent_process_name IN ("python.exe","python3","python","gunicorn","uvicorn","langflow","jupyter","jupyter-notebook","ipykernel_launcher")
    AND Processes.process_name IN ("sh","bash","zsh","dash","ksh","csh","cmd.exe","powershell.exe","pwsh.exe")
  by Processes.dest Processes.user Processes.parent_process_name Processes.parent_process
     Processes.process_name Processes.process Processes.process_id Processes.parent_process_id
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    match(parent_process, "(?i)langflow|validate.code|uvicorn|gunicorn"), 95,
    match(process_name, "(?i)powershell|pwsh"), 90,
    1=1, 80)
| where risk_score >= 80
| table firstTime lastTime dest user parent_process_name parent_process process_name process process_id risk_score
```

## Risk Score Logic

| Condition | Score | Rationale |
|-----------|-------|-----------|
| Parent process path includes `langflow`, `validate`, `gunicorn`, or `uvicorn` | 95 | Direct match on known vulnerable AI framework process names |
| Child is `powershell.exe` or `pwsh.exe` | 90 | PowerShell child of Python web server is a strong malicious indicator |
| All other Python web server → shell spawning | 80 | Any shell spawned from Python web server is anomalous |

## Associated Threat Actors

| Actor | References |
|-------|-----------|
| JadePuffer (Agentic Threat Actor) | [Sysdig — JadePuffer](https://www.sysdig.com/blog/jadepuffer-agentic-ransomware-for-automated-database-extortion) |
| MuddyWater (MOIS, Iran-nexus) | [CISA KEV — CVE-2025-34291](https://www.cisa.gov/known-exploited-vulnerabilities-catalog), [MITRE ATT&CK — MuddyWater (G0069)](https://attack.mitre.org/groups/G0069/) |
| Unknown (CVE-2025-3248 exploitation) | [NVD — CVE-2025-3248](https://nvd.nist.gov/vuln/detail/CVE-2025-3248) |

## References

- [Sysdig — JADEPUFFER: Agentic Ransomware for Automated Database Extortion (2026-07-04)](https://www.sysdig.com/blog/jadepuffer-agentic-ransomware-for-automated-database-extortion)
- [MITRE ATT&CK — T1059.006: Python](https://attack.mitre.org/techniques/T1059/006/)
- [MITRE ATT&CK — T1190: Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/)
- [NVD — CVE-2025-3248 (Langflow unauthenticated RCE)](https://nvd.nist.gov/vuln/detail/CVE-2025-3248)
- [NVD — CVE-2025-34291 (Langflow origin validation error)](https://nvd.nist.gov/vuln/detail/CVE-2025-34291)
- [CISA KEV Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
