---
scraped_at: 2026-10-23T00:00:00Z
source_url: https://socradar.io/blog/inc-gentlemen-ransomware-ai-infrastructure/
report_type: threat-intel
severity: high
title: "SOCRadar: Phantom AI Framework — INC and The Gentlemen Ransomware Affiliates Exposed Infrastructure Reveals AI-Assisted Intrusion Operations"
---

# SOCRadar: Phantom AI Framework — INC & The Gentlemen Ransomware Affiliates' AI-Assisted Intrusion Infrastructure Exposed

**Date:** 2026-10-23
**Source:** SOCRadar, Aviatrix Threat Research Center, The Hacker News
**Severity:** High
**Status:** Infrastructure exposure discovered; ~62 organizations targeted; no patch applicable (operational security failure by threat actors)

---

## Executive Summary

SOCRadar researchers discovered and analyzed an exposed command-and-control server operated by affiliates of the **INC** and **The Gentlemen** ransomware groups. The server exposed a complete AI-assisted intrusion framework called **Phantom**, including 8,257 messages across 133 AI sessions, a central knowledge base, source code for the Phantom automation framework, and configuration material that led researchers to six additional exposed adversary-controlled servers.

Phantom is an autonomous red-team-style kill chain automation framework. A human operator supplies a victim-specific prompt and approves each step, while an AI (run through OpenCode with commercial models via OpenRouter) generates and executes commands. Observed initial access vectors include FortiClient EMS, SimpleHelp, cPanel, and VPN gateways. Approximately 62 organizations have been targeted, with over 50% based in the United States.

---

## 1. IOCs

### Network Indicators

| Indicator | Type | Context |
|-----------|------|---------|
| `45.227.254[.]43` | IP address | Exposed Phantom C2/AI session server — the primary exposed infrastructure node |

### Tooling Referenced (not direct IOCs, but hunt targets)

| Tool | Type | Notes |
|------|------|-------|
| Phantom framework | AI-assisted intrusion automation | Custom framework; source code exposed on the C2 server |
| Ghost C2 | Command-and-control framework | Used alongside Phantom for post-exploitation tasking |
| RevSocks | Tunneling / SOCKS proxy | Used for network tunneling and lateral movement support |
| WormGPT-MCP | AI model access | Jailbroken model used when commercial models refuse commands |
| OpenCode | AI code execution | Runs model commands on victim systems |
| OpenRouter | AI model routing | Routes AI queries to commercial models (used for command generation) |

---

## 2. TTPs (MITRE ATT&CK)

| Tactic | Technique | ID | Notes |
|--------|-----------|-----|-------|
| Initial Access | Exploit Public-Facing Application | T1190 | FortiClient EMS, SimpleHelp, cPanel, VPN gateway exploitation as entry vectors |
| Initial Access | Valid Accounts: Default Accounts | T1078.001 | Credential reuse via harvested FortiClient EMS credentials |
| Execution | Command and Scripting Interpreter | T1059 | AI-generated shell commands executed via OpenCode |
| Defense Evasion | Masquerading | T1036 | AI operator reframes requests as "authorized red team assessment" when models refuse |
| Persistence | Remote Access Software | T1219 | SimpleHelp and Ghost C2 used for persistent remote access |
| Lateral Movement | Remote Services | T1021 | Network pivoting via RevSocks SOCKS proxy tunneling |
| Command and Control | Application Layer Protocol | T1071 | Ghost C2 over standard application protocols |
| Command and Control | Proxy: SOCKS | T1090.001 | RevSocks tunnel for C2 channel obfuscation |
| Collection | Data from Local System | T1005 | AI-directed data staging prior to exfiltration |
| Impact | Data Encrypted for Impact | T1486 | INC/The Gentlemen ransomware deployment as final stage |

---

## 3. Malware & Tools

| Name | Family | Notes |
|------|--------|-------|
| Phantom | AI intrusion automation framework | Custom autonomous kill-chain framework; human approves each AI-generated step |
| Ghost C2 | C2 framework | Post-exploitation command and control |
| RevSocks | Network tunneling | SOCKS5 proxy for lateral movement support |
| INC ransomware | Ransomware | Final payload for some victim sets |
| The Gentlemen ransomware | Ransomware | Final payload for other victim sets |
| WormGPT-MCP | Jailbroken AI model | Used as fallback when commercial models refuse malicious commands |

---

## 4. Threat Actor / Campaign Attribution

| Actor | Role | Notes |
|-------|------|-------|
| INC ransomware affiliates | Operator | INC is a ransomware-as-a-service (RaaS) group active since 2023 |
| The Gentlemen | Operator | C-based ransomware group tracked since mid-2026; prior coverage: `2026-07-08_unit42-paloaltonetworks-com-the-gentlemen-c-based-ransomware.md` |

The exposed infrastructure reveals affiliates operating both INC and The Gentlemen ransomware, sharing the Phantom framework. The operational security failure (leaving the C2 server exposed without authentication) allowed SOCRadar to enumerate the full campaign scope: 8,257 messages, 133 AI sessions, ~62 targeted organizations, >50% US-based.

**Initial access vectors observed:** FortiClient EMS (likely FortiBleED-related credential theft, see `2026-07-13_www-bleepingcomputer-com-news-security-fortibleed-credential-theft-campaign-linked-to-lynx-ransomware.md`), SimpleHelp, cPanel, VPN gateways.

---

## 5. Splunk Detection Searches

### 5a. Ghost C2 / Phantom Framework Beacon Detection

Detects network connections to unknown external hosts from processes consistent with Ghost C2 or RevSocks tunneling behavior.

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Network_Traffic.All_Traffic
    where All_Traffic.dest_ip="45.227.254.43"
        OR (All_Traffic.app=socks5 AND All_Traffic.bytes_out > 1000)
    by All_Traffic.src_ip All_Traffic.dest_ip All_Traffic.dest_port
       All_Traffic.app All_Traffic.bytes_out All_Traffic.bytes_in
| `drop_dm_object_name(All_Traffic)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    dest_ip="45.227.254.43", 95,
    app="socks5", 70,
    1=1, 50)
| where risk_score >= 70
| table firstTime lastTime src_ip dest_ip dest_port app bytes_out bytes_in risk_score
```

### 5b. SimpleHelp Remote Access Unexpected Execution

Detects SimpleHelp remote access software executing in environments where it is not an approved tool.

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Endpoint.Processes
    where Processes.process_name IN ("SimpleHelpService.exe","SimpleHelp.exe","remote.exe")
        OR Processes.process="*simplehelp*" OR Processes.process="*SimpleHelp*"
    by Processes.dest Processes.user Processes.parent_process_name
       Processes.process_name Processes.process Processes.process_id
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    match(parent_process_name, "cmd|powershell|wscript|cscript|mshta"), 90,
    1=1, 70)
| where risk_score >= 70
| table firstTime lastTime dest user parent_process_name process_name process process_id risk_score
```

### 5c. RevSocks / SOCKS Proxy Tunneling via Unexpected Process

Detects processes establishing SOCKS proxy tunneling connections on non-standard ports, consistent with RevSocks behavior.

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Network_Traffic.All_Traffic
    where All_Traffic.app=socks5 OR All_Traffic.dest_port IN (1080,1081,1082,8888,9050,9150)
    by All_Traffic.src_ip All_Traffic.src_port All_Traffic.dest_ip All_Traffic.dest_port
       All_Traffic.app All_Traffic.process_name
| `drop_dm_object_name(All_Traffic)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    process_name IN ("revsocks","socks","tunnel"), 90,
    dest_port=9050 OR dest_port=9150, 55,
    1=1, 65)
| where risk_score >= 55
| table firstTime lastTime src_ip src_port dest_ip dest_port app process_name risk_score
```

---

## 6. Executive Summary

SOCRadar researchers discovered a publicly exposed Phantom AI intrusion framework server operated by affiliates of the INC and The Gentlemen ransomware groups. The exposure revealed 133 AI-assisted attack sessions targeting approximately 62 organizations, with over 50% in the United States. The Phantom framework is a human-supervised, AI-executed kill chain: an operator provides a victim-specific prompt and approves each generated step, while OpenCode drives command execution through commercial AI models (via OpenRouter). When commercial models refuse to assist, operators use WormGPT-MCP as a fallback.

Initial access leverages exploitation of FortiClient EMS, SimpleHelp remote access, cPanel, and VPN gateways. Post-exploitation uses Ghost C2 for persistent access and RevSocks for network tunneling. The exposed C2 server at `45.227.254[.]43` should be blocked at perimeter controls. Organizations should audit for SimpleHelp installations and unexpected SOCKS proxy activity.

This represents a documented case of AI-assisted intrusion automation being used at scale in real ransomware operations, extending the earlier JadePuffer (`2026-07-21`) and Artex AI (`2026-10-08`) precedents.

---

## References

- [SOCRadar — INC and The Gentlemen Ransomware: Exposed AI Infrastructure](https://socradar.io/blog/inc-gentlemen-ransomware-ai-infrastructure/)
- [Aviatrix Threat Research — Phantom AI Framework: Exposed Infrastructure](https://aviatrix.ai/threat-research-center/exposed-infrastructure-phantom-ai-ransomware-affiliates-inc-gentlemen-2026/)
- [The Hacker News — Exposed Infrastructure Reveals How Ransomware Affiliates Used AI Agents to Execute Intrusions](https://thehackernews.com/2026/10/exposed-infrastructure-reveals-how.html)
- [Prior INC/Gentlemen coverage — 2026-10-05 Azazel MCP C2](../threat-intel/2026-10-05_cloudsek-com-gentlemen-azazel-mcp-c2-gitlab-cicd-ransomware.md)
- [Prior INC/Gentlemen coverage — 2026-07-08 Unit 42 The Gentlemen](../threat-intel/2026-07-08_unit42-paloaltonetworks-com-the-gentlemen-c-based-ransomware.md)
- [MITRE ATT&CK — T1219 Remote Access Software](https://attack.mitre.org/techniques/T1219/)
- [MITRE ATT&CK — T1486 Data Encrypted for Impact](https://attack.mitre.org/techniques/T1486/)
- [MITRE ATT&CK — T1090.001 Proxy: Internal Proxy](https://attack.mitre.org/techniques/T1090/001/)
