# Langflow CVE-2026-0768: Unauthenticated Python Code Execution and Credential Harvesting

## Description

Detects active exploitation of **CVE-2026-0768**, a critical (CVSS 9.8) unauthenticated remote code execution vulnerability in the Langflow AI workflow orchestration framework. The flaw exists in an unguarded `exec()` call in a Langflow API endpoint, allowing any unauthenticated attacker to execute arbitrary Python code on the host.

Observed exploitation activity (confirmed by VulnCheck, September 1, 2026) shows attackers:
1. Executing OS commands from Langflow's Python runtime
2. Probing for high-value credentials via environment variables (`LANGFLOW_SUPERUSER`, `OPENAI_API*`, `AWS_ACCESS*`, `AWS_SECRET*`)
3. Reading the Langflow local secret key at `/root/.cache/langflow/secret_key`
4. Probing SSH configuration and `.bash_history` file sizes
5. Establishing C2 to an Israel-based host

Attack traffic originated from France (CVE-2026-66066 Rails correlation) and Russia, targeting canary systems in UK, Singapore, and Israel.

This is distinct from CVE-2025-3248 (earlier Langflow RCE covered in `python_web_framework_os_command_execution.md`); CVE-2026-0768 is a separate code path and is already under active exploitation.

**False positive sources:**
- Legitimate Langflow administrators testing flows via the API
- Security researchers or red teams with authorized access

## MITRE ATT&CK Mapping

- **Tactic:** Execution (TA0002)
- **Technique:** Command and Scripting Interpreter: Python (T1059.006)
- **Secondary Tactic:** Initial Access (TA0001)
- **Secondary Technique:** Exploit Public-Facing Application (T1190)
- **Secondary Tactic:** Credential Access (TA0006)
- **Secondary Technique:** Unsecured Credentials: Environment Variables (T1552.007)
- **Secondary Technique:** Unsecured Credentials: Credentials in Files (T1552.001)
- **Secondary Tactic:** Command and Control (TA0011)
- **Secondary Technique:** Application Layer Protocol: Web Protocols (T1071.001)

## Lockheed Martin Kill Chain Phase

**Exploitation** (CVE-2026-0768 exec), **Actions on Objectives** (credential harvest for cloud/AI platform account takeover)

## Splunk SPL Query

### Rule 1 — Langflow/Python Web Server Spawning Shell (Endpoint)

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Processes
  where Processes.parent_process_name IN ("langflow","python3","python","uvicorn","gunicorn","hypercorn")
    AND Processes.process_name IN ("sh","bash","dash","curl","wget","id","whoami","cat","env",
                                    "printenv","python3","python","nc","ncat","perl","ruby")
  by Processes.dest Processes.user Processes.parent_process_name Processes.process_name
     Processes.process Processes.process_id Processes.parent_process_id
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    match(process, "(?i)(LANGFLOW_SUPERUSER|OPENAI_API|AWS_ACCESS|AWS_SECRET|secret_key)"), 95,
    match(process, "(?i)(env|printenv|cat\s+/root/|cat\s+/home/)"), 85,
    match(process, "(?i)(wget|curl).*(http)"), 80,
    match(process, "(?i)(whoami|id|uname)"), 70,
    match(process, "(?i)(nc|ncat|netcat).+(-e|-c|bash)"), 95,
    true(), 60)
| where risk_score >= 60
| table firstTime lastTime dest user parent_process_name process_name process risk_score
```

### Rule 2 — Environment Variable Credential Probe (Endpoint)

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Processes
  where (Processes.process_name IN ("env","printenv","python3","python","sh","bash")
         AND Processes.parent_process_name IN ("langflow","python3","uvicorn","gunicorn","hypercorn"))
     OR Processes.process IN ("*LANGFLOW_SUPERUSER*","*OPENAI_API_KEY*","*AWS_ACCESS_KEY*","*AWS_SECRET_ACCESS_KEY*")
  by Processes.dest Processes.user Processes.process_name Processes.process
     Processes.parent_process_name Processes.process_id
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| table firstTime lastTime dest user process_name process parent_process_name process_id
```

### Rule 3 — Langflow Secret Key File Read (Endpoint Filesystem)

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Filesystem
  where (Filesystem.file_path="/root/.cache/langflow/secret_key"
     OR Filesystem.file_path="/home/*/.cache/langflow/secret_key"
     OR Filesystem.file_path="/root/.cache/langflow/*")
    AND Filesystem.action="read"
  by Filesystem.dest Filesystem.user Filesystem.file_path Filesystem.process_name
| `drop_dm_object_name(Filesystem)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| table firstTime lastTime dest user file_path process_name
```

### Rule 4 — Unauthenticated Langflow API Exploit Attempts (Web / Proxy)

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Web.Web
  where Web.http_method="POST"
    AND (Web.url IN ("*/api/v1/predict/*","*/api/v2/flows/*/run","*/api/v1/build/*","*/api/v1/run/*"))
  by Web.src Web.dest Web.url Web.status Web.bytes_in Web.bytes_out Web.user_agent
| `drop_dm_object_name(Web)`
| where match(user_agent, "(?i)(python-requests|curl|wget|go-http|nuclei|httpx|sqlmap)")
     OR (isnull(user_agent) OR user_agent="")
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| stats count min(firstTime) as firstTime max(lastTime) as lastTime by src dest url status user_agent
| where count > 5
| table firstTime lastTime src dest url status count user_agent
```

## Risk Score Logic

| Score | Condition |
|-------|-----------|
| 95 | Python child process enumerating `LANGFLOW_SUPERUSER`, `OPENAI_API_KEY`, `AWS_ACCESS_KEY_ID`, or `AWS_SECRET_ACCESS_KEY` |
| 95 | Langflow parent spawning reverse shell (`nc`/`ncat` with `-e`/`-c bash`) |
| 90 | Read access to `/root/.cache/langflow/secret_key` by non-Langflow process |
| 85 | Python child reading `/root/`, `/home/`, or running `printenv`/`env` |
| 80 | Python child downloading files via `curl`/`wget` |
| 70 | Python child running recon commands (`whoami`, `id`, `uname`) |
| 60 | Automated tool POSTing to Langflow execution API endpoints |

## Associated Threat Actors

| Actor | Notes |
|-------|-------|
| Unattributed (France-origin) | Single French IP; active exploitation of CVE-2026-0768; C2 to Israeli host; correlated with CVE-2026-66066 Rails exploitation; targeting UK, Singapore, Israel canary systems |
| Unattributed (Russia-origin) | Langflow CVE-2026-0768 exploitation targeting UK canary systems; credential harvesting focus (AI platform keys, cloud credentials) |
| JadePuffer (Agentic Ransomware) | Previously exploited CVE-2025-3248 (Langflow); likely to adapt to CVE-2026-0768 given identical attack surface; autonomous LLM-driven ransomware targeting AI credential stores |

## References

- [The Hacker News: Attackers Exploit Critical Langflow and Rails Flaws](https://thehackernews.com/2026/09/attackers-exploit-critical-langflow-and.html)
- [SOCRadar: Langflow and Rails Exploitation Raises Credential Risks](https://socradar.io/blog/langflow-ruby-on-rails-flaws-exploited/)
- [Dark Reading: Critical Langflow Flaw Exploited](https://www.darkreading.com/vulnerabilities-threats/critical-langflow-flaw-exploited-attacks-rise)
- [CSA Research: Langflow AI Framework Credential Harvesting](https://labs.cloudsecurityalliance.org/research/csa-research-note-langflow-ai-framework-credential-harvestin/)
- [NVD CVE-2026-0768](https://nvd.nist.gov/vuln/detail/CVE-2026-0768)
- [MITRE ATT&CK T1059.006 — Command and Scripting Interpreter: Python](https://attack.mitre.org/techniques/T1059/006/)
- [MITRE ATT&CK T1552.007 — Unsecured Credentials: Environment Variables](https://attack.mitre.org/techniques/T1552/007/)
- [MITRE ATT&CK T1190 — Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/)
