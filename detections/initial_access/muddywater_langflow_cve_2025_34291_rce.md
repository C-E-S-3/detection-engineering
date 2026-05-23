# MuddyWater Langflow AI Platform RCE Exploitation (CVE-2025-34291)

## Description

Detects exploitation of CVE-2025-34291, a critical (CVSS 9.4) origin validation error in the Langflow AI agent and workflow platform. The vulnerability combines three weaknesses: overly permissive CORS headers, missing CSRF protection, and an API endpoint (`/api/v1/validate/code`) that executes arbitrary Python code by design. Successful exploitation achieves unauthenticated remote code execution on the Langflow server and exposes all API keys and tokens stored in the workspace.

The Iran-nexus APT group **MuddyWater** has actively exploited this vulnerability since January 2026, using modified exploit scripts communicating with known MuddyWater C&C infrastructure. The Flodric botnet has also been deployed via compromised Langflow instances.

This detection covers three angles:
1. **Subprocess spawning**: Shell or scripting processes unexpectedly spawned as children of the Langflow Python process.
2. **Known C2 network indicator**: Outbound connections to the MuddyWater C&C IP `194.11.246.101`.
3. **Web API abuse**: Unauthenticated or cross-origin HTTP POST requests to Langflow's code-execution endpoints.

**False positives (process-spawn):** Legitimate Langflow workflows that use the "Subprocess" or "CustomPython" component to invoke shell commands. Review `process` (command line) and `dest` to confirm this is an unexpected host or invocation.

## MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| Tactic | Initial Access |
| Tactic ID | TA0001 |
| Technique | Exploit Public-Facing Application |
| Technique ID | T1190 |
| Secondary Tactic | Execution |
| Secondary Technique ID | T1059.006 (Python) |

## Lockheed Martin Kill Chain

| Phase |
|-------|
| Exploitation |

## Splunk Detection Query

### Query 1 — Subprocess Spawning from Langflow Process

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Endpoint.Processes
where Processes.parent_process_name IN ("python.exe","python3","python","langflow")
  AND Processes.process_name IN ("cmd.exe","sh","bash","powershell.exe","pwsh",
      "whoami","id","curl","wget","nc","ncat","nmap")
by Processes.dest Processes.user Processes.parent_process_name
   Processes.process_name Processes.process Processes.process_id
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    match(process_name,"(?i)(powershell\.exe|pwsh|cmd\.exe)"), 90,
    match(process_name,"(?i)(curl|wget|nc|ncat)"), 85,
    match(process_name,"(?i)(whoami|id|bash|sh)"), 80,
    1=1, 70)
| where risk_score >= 80
| table firstTime lastTime dest user parent_process_name process_name process process_id risk_score
```

### Query 2 — Outbound Connection to MuddyWater C&C IP

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Network_Traffic.All_Traffic
where All_Traffic.dest="194.11.246.101"
by All_Traffic.src All_Traffic.dest All_Traffic.dest_port All_Traffic.app
| `drop_dm_object_name(All_Traffic)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=100
| table firstTime lastTime src dest dest_port app count risk_score
```

### Query 3 — Suspicious HTTP POST to Langflow Code Execution Endpoint

```spl
`web` (uri_path="/api/v1/validate/code" OR uri_path="/api/v1/run/*") http_method=POST
| eval is_external=if(match(src_ip,"^(127\.|10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.)"),0,1)
| eval risk_score=case(
    uri_path="/api/v1/validate/code" AND is_external=1, 95,
    uri_path="/api/v1/validate/code" AND is_external=0, 75,
    match(uri_path,"/api/v1/run/") AND is_external=1, 80,
    match(uri_path,"/api/v1/run/") AND is_external=0, 55,
    1=1, 50)
| where risk_score >= 75
| stats count values(uri_path) as paths values(http_user_agent) as user_agents
    min(_time) as firstTime max(_time) as lastTime by src_ip dest risk_score
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| table firstTime lastTime src_ip dest paths user_agents count risk_score
```

## Risk Score Logic

| Condition | Score | Rationale |
|-----------|-------|-----------|
| POST to `/api/v1/validate/code` from external IP | 95 | Direct code execution endpoint accessed externally — near-certain exploitation attempt |
| POST to `/api/v1/validate/code` from internal IP | 75 | Internal access to code exec endpoint is suspicious unless from known admin host |
| POST to `/api/v1/run/*` from external IP | 80 | Flow execution from untrusted source may be part of CSRF-bypass exploit chain |
| Outbound connection to 194.11.246.101 | 100 | Known MuddyWater C&C infrastructure — confirmed malicious |
| Shell/scripting child of Python/Langflow process | 80–90 | Unexpected code execution via subprocess in Langflow context |

## Associated Threat Actors

| Actor | References |
|-------|-----------|
| MuddyWater (MOIS, G0069) | [MITRE ATT&CK — MuddyWater](https://attack.mitre.org/groups/G0069/), [Ctrl-Alt-Intel — MuddyWater Exposed](https://ctrlaltintel.com/threat%20research/MuddyWater/) |
| Unknown botnet operator (Flodric) | [Security Affairs — Langflow KEV](https://securityaffairs.com/192529/hacking/u-s-cisa-adds-trend-micro-apex-one-and-langflow-to-its-known-exploited-vulnerabilities-catalog.html) |

## References

- [CISA KEV — May 21, 2026 Additions](https://www.cisa.gov/news-events/alerts/2026/05/21/cisa-adds-two-known-exploited-vulnerabilities-catalog)
- [The Hacker News — CISA Adds Exploited Langflow Vulnerability to KEV](https://thehackernews.com/2026/05/cisa-adds-exploited-langflow-and-trend.html)
- [CrowdSec — CVE-2025-34291 Exploited in the Wild](https://www.crowdsec.net/vulntracking-report/cve-2025-34291)
- [Obsidian Security — CVE-2025-34291 Technical Analysis](https://www.obsidiansecurity.com/blog/cve-2025-34291-critical-account-takeover-and-rce-vulnerability-in-the-langflow-ai-agent-workflow-platform)
- [MITRE ATT&CK — T1190: Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/)
