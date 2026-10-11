# Gentlemen/Azazel — MCP Server Repurposed as Local C2 Channel (First Documented MCP-as-C2)

## Description

Detects adversarial use of the Model Context Protocol (MCP) as a command-and-control channel, as first documented in the Gentlemen/Azazel ransomware affiliate campaign (Storm-2697, October 2026). MCP is an open standard originally designed for AI assistant tool integrations; it defines a JSON-RPC protocol for invoking "tools" (functions) via a local or remote server.

In this campaign, the threat actor (Azazel) installed an MCP server on victim systems listening on `127.0.0.1:35367` and issued shell commands via the `exec_in_session` MCP tool call, authenticated with a fixed bearer token. Because the MCP server listens only on loopback and all traffic stays local, traditional network-based C2 detection is bypassed entirely. Detection requires endpoint-level monitoring.

The specific port `35367` has no known legitimate MCP server assignment; common development MCP servers use configurable or well-known ports (3000, 5000, 8080, etc.). Shell processes spawned from Node.js or Python runtimes in non-development paths are a secondary indicator.

False positives: Development environments legitimately run MCP servers (e.g., Claude Desktop, Cursor, VS Code extensions). Context — the process path, parent chain, and whether the system is a developer workstation — is essential for triage. On non-developer systems (servers, endpoints without IDE tooling), any MCP server process on port 35367 is high confidence malicious.

## MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| Tactic | Command and Control |
| Tactic ID | TA0011 |
| Technique | Application Layer Protocol |
| Technique ID | T1071 |
| Secondary Techniques | T1059 (Command and Scripting Interpreter), T1564 (Hide Artifacts) |

## Lockheed Martin Kill Chain

| Phase |
|-------|
| Command & Control (C2) |

## Splunk Detection Query

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Network_Traffic.All_Traffic
  where All_Traffic.dest_port=35367
    AND (All_Traffic.dest="127.0.0.1" OR All_Traffic.dest="::1")
  by All_Traffic.src All_Traffic.dest All_Traffic.dest_port All_Traffic.transport All_Traffic.app
| `drop_dm_object_name(All_Traffic)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    match(lower(app), "(node|python|java|go)"), 85,
    1=1, 75)
| where risk_score >= 75
| table firstTime lastTime src dest dest_port transport app risk_score
```

## Risk Score Logic

| Condition | Score | Rationale |
|-----------|-------|-----------|
| Port 35367 traffic from Node.js/Python/Go/Java runtime | 85 | High — specific port with a runtime associated with MCP server implementations |
| Any traffic to loopback port 35367 | 75 | High — no known legitimate service uses this port; specific to observed Azazel TTP |

## Associated Threat Actors

| Actor | References |
|-------|-----------|
| Azazel (Gentlemen ransomware affiliate, Storm-2697) | [CloudSEK Blog — Caught in 4K: The Gentlemen Files](https://www.cloudsek.com/blog/caught-in-4k-the-gentlemen-files) |
| The Gentlemen (Storm-2697) | [MITRE ATT&CK T1071 — Application Layer Protocol](https://attack.mitre.org/techniques/T1071/) |

## References

- [CloudSEK Blog — Caught in 4K: The Gentlemen Files](https://www.cloudsek.com/blog/caught-in-4k-the-gentlemen-files)
- [Model Context Protocol Specification](https://modelcontextprotocol.io/specification)
- [MITRE ATT&CK T1071 — Application Layer Protocol](https://attack.mitre.org/techniques/T1071/)
- [MITRE ATT&CK T1078.004 — Valid Accounts: Cloud Accounts](https://attack.mitre.org/techniques/T1078/004/)
- [MITRE ATT&CK T1486 — Data Encrypted for Impact](https://attack.mitre.org/techniques/T1486/)
