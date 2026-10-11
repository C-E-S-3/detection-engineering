---
scraped_at: "2026-10-11T00:00:00Z"
source_url: "https://www.cloudsek.com/blog/caught-in-4k-the-gentlemen-files"
report_type: threat-intel
severity: critical
title: "The Gentlemen / Azazel Ransomware Affiliate — First Publicly Documented MCP-as-C2; GitLab CI/CD Initial Access; 24+ Victims Across 6 Countries"
---

# The Gentlemen / Azazel Ransomware Affiliate — First Publicly Documented MCP-as-C2; GitLab CI/CD Initial Access; 24+ Victims Across 6 Countries

## 1. IOCs

### Domains

| Indicator | Context |
|-----------|---------|
| `forgitlab[.]com` | Azazel/Gentlemen campaign infrastructure — typosquat domain mimicking GitLab used in initial access phishing and credential harvesting targeting GitLab CI/CD workflows |

### Infrastructure Notes

No specific IP addresses confirmed for public attribution at time of reporting.

The actor operated an independent ransomware leak site named **LEAKNED** in addition to The Gentlemen's primary leak site. The campaign involved approximately 29 TB of stolen data across two exfiltration servers.

## 2. TTPs (MITRE ATT&CK)

| Tactic | Technique | ID | Notes |
|--------|-----------|-----|-------|
| Initial Access | Valid Accounts: Cloud Accounts | T1078.004 | CI/CD secrets and service account credentials harvested from exposed GitLab instances; used to authenticate into victim environments |
| Initial Access | Phishing | T1566 | `forgitlab[.]com` typosquat domain used to harvest GitLab credentials from developers |
| Execution | Command and Scripting Interpreter | T1059 | Commands executed via MCP `exec_in_session` tool invocations delivered over local loopback MCP server |
| Command and Control | Application Layer Protocol | T1071 | **NOVEL TTP:** Model Context Protocol (MCP) server on `127.0.0.1:35367` used as local C2 relay; commands encoded as MCP tool calls (`exec_in_session`) with a fixed bearer token; first publicly documented use of MCP as C2 channel |
| Defense Evasion | Trusted Developer Utilities Proxy Execution | T1127 | CI/CD pipeline stages abused to execute malicious code within trusted build contexts |
| Defense Evasion | Hide Artifacts | T1564 | MCP server masquerades as a development tool component; traffic appears as local loopback communication, bypassing network-based detection |
| Collection | Data from Local System | T1005 | Mass data exfiltration — 29 TB across two servers |
| Impact | Data Encrypted for Impact | T1486 | Gentlemen ransomware deployed for file encryption |
| Impact | Defacement / Exfiltration for Leverage | T1491 | Data published to LEAKNED leak site operated independently by Azazel |

## 3. Malware & Tools

| Name | Type | Description |
|------|------|-------------|
| Gentlemen Ransomware | Ransomware | RaaS platform operated by Storm-2697; affiliate Azazel deployed this payload post-exfiltration |
| MCP C2 Relay | Novel C2 component | A Model Context Protocol (MCP) server installed on the victim's local system at `127.0.0.1:35367`; the attacker invokes `exec_in_session` MCP tool calls with a fixed bearer token to achieve remote command execution via what appears to be local loopback traffic. First documented case of MCP being repurposed as a C2 channel. |

## 4. Threat Actor / Campaign Attribution

**Threat Actor:** Azazel (alias; individual ransomware affiliate)
**Associated Group:** The Gentlemen ransomware operation (tracked by Microsoft as **Storm-2697**)
**Suspected Origin:** Russian-speaking; attributed based on forum language and operational patterns
**Leak Site:** LEAKNED (operated independently by Azazel in addition to The Gentlemen's primary site)

**Campaign scope:**
- **24+ confirmed victims** across 6 countries
- **29 TB** of data stolen and staged across 2 servers
- Target sectors: not fully disclosed; consistent with broad ransomware targeting

**Novel TTP — MCP-as-C2:** This campaign is the first publicly documented use of the Model Context Protocol (MCP) as a command-and-control channel. MCP is an open standard originally designed for AI assistant tool integrations; it defines a JSON-RPC-based protocol for invoking "tools" (functions) through a local or remote server. Azazel installed an MCP server on victim systems listening on the loopback interface (`127.0.0.1:35367`) and used the `exec_in_session` tool to issue shell commands, authenticated with a fixed bearer token embedded in requests. This technique blends into AI development tooling noise (many developers legitimately run MCP servers) and produces only loopback traffic, making network-based C2 detection ineffective. Detection requires endpoint-level process and service monitoring.

**Initial access vector:** Exposed or misconfigured GitLab instances. Specifically:
- Credentials and CI/CD secrets harvested from repositories with insufficiently protected CI/CD variable stores
- The `forgitlab[.]com` typosquat domain was used in social engineering to collect additional GitLab credentials
- Once inside the CI/CD pipeline, malicious stages were inserted to achieve code execution within trusted build workers

## 5. Splunk Detection Searches

### Search 1: MCP Server Process Listening on Local Port 35367

Detects processes binding to TCP port 35367 on the loopback interface — the specific port used by the Azazel MCP C2 component. Legitimate MCP servers commonly run on different ports; this specific port has no known benign assignment.

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Network_Traffic.All_Traffic
  where All_Traffic.dest_port=35367
    AND (All_Traffic.dest="127.0.0.1" OR All_Traffic.dest="::1" OR All_Traffic.dest="localhost")
  by All_Traffic.src All_Traffic.dest All_Traffic.dest_port All_Traffic.transport
| `drop_dm_object_name(All_Traffic)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=85
| table firstTime lastTime src dest dest_port transport risk_score
```

### Search 2: Suspicious Process Spawned from MCP-Style Parent

Detects shell commands (`cmd.exe`, `powershell.exe`, `bash`, `sh`) spawned by processes that have characteristics consistent with MCP server processes — particularly Node.js, Python, or Go runtimes in non-development system paths.

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Processes
  where (Processes.process_name="cmd.exe" OR Processes.process_name="powershell.exe"
    OR Processes.process_name="bash" OR Processes.process_name="sh")
    AND (Processes.parent_process_name="node.exe" OR Processes.parent_process_name="node"
      OR Processes.parent_process_name="python.exe" OR Processes.parent_process_name="python3"
      OR Processes.parent_process_name="python")
  by Processes.dest Processes.user Processes.parent_process_name
     Processes.process_name Processes.process Processes.process_id Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    like(lower(process_path), "%system32%"), 90,
    like(lower(process_path), "%temp%"), 85,
    like(lower(process_path), "%appdata%"), 80,
    1=1, 65)
| where risk_score >= 65
| table firstTime lastTime dest user parent_process_name process_name process process_path risk_score
```

### Search 3: CI/CD Secret Exposure — GitLab Variable Access Patterns

Detects unusual access patterns in GitLab CI/CD pipeline execution logs that may indicate credential harvesting from protected CI/CD variables. Requires forwarding GitLab audit logs to Splunk.

```spl
index=* sourcetype="gitlab:audit" action_type="download_export"
    OR (sourcetype="gitlab:audit" action_type="ci_variable" event_type="access")
| eval risk_score=case(
    action_type="download_export", 75,
    action_type="ci_variable" AND match(details, "protected"), 80,
    1=1, 50)
| where risk_score >= 50
| table _time user ip action_type details risk_score
| sort -risk_score
```

### Search 4: DNS Lookup for forgitlab[.]com Typosquat Domain

Detects DNS queries for the confirmed Azazel/Gentlemen campaign domain `forgitlab.com`.

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Network_Resolution.DNS
  where DNS.query="forgitlab.com" OR DNS.query="*.forgitlab.com"
  by DNS.src DNS.query DNS.record_type DNS.answer
| `drop_dm_object_name(DNS)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=95
| table firstTime lastTime src query record_type answer risk_score
```

## 6. Executive Summary

CloudSEK published research on October 5, 2026 documenting the Azazel ransomware affiliate's campaign against 24+ organizations across 6 countries. Azazel operates as an affiliate of The Gentlemen ransomware operation (Storm-2697), a Russian-speaking ransomware-as-a-service group. The campaign is notable for two reasons:

**1. MCP-as-C2 (novel):** This is the first publicly documented use of the Model Context Protocol as a command-and-control channel. MCP, an open standard for AI tool integrations, was repurposed as a C2 relay: the actor installed an MCP server on victim systems at `127.0.0.1:35367` and issued shell commands through the `exec_in_session` MCP tool call, authenticated with a fixed bearer token. Because MCP traffic over loopback is indistinguishable from legitimate AI development activity and produces no external network connections, traditional C2 detection controls are bypassed. Detection requires endpoint-level monitoring for processes binding to port 35367 and shell processes spawned from runtimes associated with MCP servers (Node.js, Python).

**2. GitLab CI/CD initial access:** The actor harvested CI/CD secrets and credentials from exposed GitLab instances. The domain `forgitlab[.]com` was used to phish developer credentials. Once inside CI/CD pipelines, malicious build stages executed the intrusion toolkit within trusted build worker contexts.

The confirmed domain IOC `forgitlab[.]com` should be blocked at DNS and web proxy. Organizations should audit GitLab CI/CD variable stores for unnecessary secrets, enforce protected-variable requirements, and deploy endpoint monitoring capable of detecting MCP server processes on non-standard ports.

## References

- [CloudSEK Blog — Caught in 4K: The Gentlemen Files](https://www.cloudsek.com/blog/caught-in-4k-the-gentlemen-files)
- [MITRE ATT&CK T1071 — Application Layer Protocol](https://attack.mitre.org/techniques/T1071/)
- [MITRE ATT&CK T1078.004 — Valid Accounts: Cloud Accounts](https://attack.mitre.org/techniques/T1078/004/)
- [MITRE ATT&CK T1486 — Data Encrypted for Impact](https://attack.mitre.org/techniques/T1486/)
- [Model Context Protocol Specification](https://modelcontextprotocol.io/specification)
- [Microsoft Storm-2697 Threat Actor Profile](https://www.microsoft.com/en-us/security/blog/threat-intelligence)
