---
scraped_at: "2026-09-26T00:00:00Z"
source_url: "https://cloud.google.com/blog/topics/threat-intelligence/shinyhunters-renewed-mass-exploitation-campaign-targeting-oracle-peoplesoft"
report_type: threat-intel
severity: critical
title: "ShinyHunters (UNC6240) Renewed Mass Exploitation Campaign Targeting Oracle PeopleSoft — WAF Bypass, SIDEEYE Backdoor, Neo-reGeorg SOCKS5 Tunneling"
---

# Google GTIG — ShinyHunters (UNC6240) Renewed Oracle PeopleSoft Exploitation (September 25, 2026)

## Executive Summary

Google Threat Intelligence Group (GTIG) published a renewed campaign assessment on September 25, 2026, detailing a second mass exploitation wave by **UNC6240 (ShinyHunters)** against Oracle PeopleSoft using the same critical RCE vulnerability, **CVE-2026-35273** (CVSS 9.8), first exploited in their May–June 2026 campaign. This renewed wave (approximately September 10–24, 2026) bypasses web application firewalls that added signature rules after the June disclosure via a percent-encoded URI path (`/%50SEMHUB/` instead of `/PSEMHUB/`), exploiting the WAF's failure to normalize percent-encoded characters before rule evaluation.

The renewed campaign introduces a more capable toolset: three new web shells deployed inside `PSEMHUB.war` (x.jsp, u.jsp, and Neo-reGeorg SOCKS5 tunneling shells), a new custom backdoor **SIDEEYE** (a trojanized Light Alloy media player binary packed with VMProtect 3), and MeshAgent pointed at a new C2 domain (`winmanage-me.network`). Target scope has widened beyond higher education to include technology, healthcare, government, agriculture, and transportation sectors globally.

---

## 1. IOCs

### IP Addresses
| Indicator | Context |
|-----------|---------|
| `5.199.162.157` | UNC6240 attack controller; source of CVE-2026-35273 exploitation attempts |
| `104.219.234.138` | UNC6240 exfiltration staging server |
| `162.219.30.165` | SIDEEYE backdoor C2 listener; accepts TCP connections on ports 3333 and 3334 |

### Domains
| Indicator | Context |
|-----------|---------|
| `winmanage-me.network` | UNC6240 MeshCentral C2 domain; MeshAgent WebSocket endpoint `wss://winmanage-me.network:443/agent.ashx`; masquerades as Windows remote management service |

### File Hashes (SHA-256)
| Hash | Filename | Context |
|------|----------|---------|
| `48b4a0827da7bbfce9fb52464f8a659dea7a035189c52c506c0bfb4b1c3fe494` | `x.jsp` | Command execution web shell deployed to `PSEMHUB.war`; accepts `cmd` parameter via POST |
| `2bee941fb40519d0d1ec52bd79a8f63fc65aac6455c8f2d6b668e3360dfdb5d7` | `u.jsp` | File upload web shell deployed to `PSEMHUB.war`; used for payload staging |
| `419c571ee38b7e7266d130c4b6bbc4dd0ef44d6e5f3bc02cc2cf73b762f07c86` | `tunnel.jsp` | Neo-reGeorg SOCKS5 tunnel web shell; routes actor tooling through PeopleSoft as SOCKS proxy |
| `ba14419beb2ec0bb94cab6298c14d7fb3e1d819366fe378290c0c2a4d97f7e07` | `tunnel.jspx` | Neo-reGeorg SOCKS5 tunnel (JSPX variant); functionally equivalent to tunnel.jsp |
| `3ba215692665513abfffd4e815c5c45f2d41e5dcc4283a2a3b740930c5c417c3` | `Ple64.exe` | SIDEEYE backdoor; trojanized Light Alloy v4.9.1 media player binary; VMProtect 3 packed; TCP C2 on ports 3333/3334 to 162.219.30.165 |

### Host-Based Indicators
The following files placed inside the `PSEMHUB.war` deployment directory indicate active compromise:

```
<PS_CFG_HOME>/webserv/<domain>/applications/peoplesoft/PSEMHUB.war/x.jsp
<PS_CFG_HOME>/webserv/<domain>/applications/peoplesoft/PSEMHUB.war/u.jsp
<PS_CFG_HOME>/webserv/<domain>/applications/peoplesoft/PSEMHUB.war/u2.jsp
<PS_CFG_HOME>/webserv/<domain>/applications/peoplesoft/PSEMHUB.war/Ple64.exe
<PS_CFG_HOME>/webserv/<domain>/applications/peoplesoft/PSEMHUB.war/tunnel.jsp
<PS_CFG_HOME>/webserv/<domain>/applications/peoplesoft/PSEMHUB.war/tunnel.jspx
```

### WAF Bypass Pattern
| Pattern | Context |
|---------|---------|
| `/%50SEMHUB/` (URI path) | Percent-encoded P (`%50` = ASCII `P`) used to bypass WAF signatures matching literal `/PSEMHUB/`; affected WAF configs that don't normalize percent-encoding before rule evaluation |

---

## 2. TTPs (MITRE ATT&CK)

| Tactic | Technique ID | Technique Name | Usage |
|--------|-------------|----------------|-------|
| Reconnaissance | T1596.003 | Search Open Technical Databases | Shodan/Censys scanning to identify internet-exposed PeopleSoft EMHub instances |
| Reconnaissance | T1595.002 | Active Scanning: Vulnerability Scanning | Mass scanning for `/%50SEMHUB/` (WAF bypass path) to identify WAF-protected but exploitable targets |
| Initial Access | T1190 | Exploit Public-Facing Application | Unauthenticated RCE via CVE-2026-35273 (XMLDecoder deserialization) using percent-encoded WAF bypass `/%50SEMHUB/hub` |
| Defense Evasion | T1027 | Obfuscated Files or Information | Percent-encoding of URI path (`%50SEMHUB`) to bypass WAF signatures; VMProtect 3 packing of SIDEEYE backdoor |
| Persistence | T1505.003 | Server Software Component: Web Shell | x.jsp, u.jsp, tunnel.jsp, tunnel.jspx deployed inside `PSEMHUB.war` Java WAR directory; survives partial cleanup |
| Execution | T1059.004 | Command and Scripting Interpreter: Unix Shell | Shell commands issued via x.jsp web shell to enumerate host and download additional payloads |
| Discovery | T1082 | System Information Discovery | Enumerate PeopleSoft config (tools.properties, psappsrv.cfg) for database credentials and internal hostnames |
| Discovery | T1016 | System Network Configuration Discovery | Parse network config to map internal PeopleSoft topology for lateral movement targeting |
| Credential Access | T1552.001 | Unsecured Credentials: Credentials in Files | Harvest database passwords and service account credentials from PeopleSoft application config files |
| Command and Control | T1090 | Proxy | Neo-reGeorg SOCKS5 tunnel (tunnel.jsp/tunnel.jspx) routes actor tooling through compromised PeopleSoft host |
| Command and Control | T1219 | Remote Access Software | MeshAgent deployed pointing to `winmanage-me.network` C2; persistent remote access after web shell eviction |
| Command and Control | T1573 | Encrypted Channel | SIDEEYE backdoor maintains encrypted TCP C2 channel to 162.219.30.165 on ports 3333/3334 |
| Exfiltration | T1048 | Exfiltration Over Alternative Protocol | Data staged for exfiltration via 104.219.234.138 using out-of-band protocol |

---

## 3. Malware & Tools

| Tool | Type | Details |
|------|------|---------|
| x.jsp | Web Shell | Command execution shell accepting `cmd` POST parameter; deployed in PSEMHUB.war directory; minimal obfuscation |
| u.jsp | Web Shell | File upload shell for staging payloads into the WAR directory; second-stage dropper mechanism |
| tunnel.jsp / tunnel.jspx | Web Shell (SOCKS5 Proxy) | Neo-reGeorg SOCKS5 tunnel implementation; transforms compromised PeopleSoft server into a proxy hop for actor tooling; password-protected channel |
| SIDEEYE (`Ple64.exe`) | Custom Backdoor | Trojanized Light Alloy v4.9.1 (Russian freeware media player); packed with VMProtect 3 to hinder analysis; maintains persistent encrypted TCP C2 to 162.219.30.165:3333-3334; provides full remote access; GTIG assessed as newly developed capability specific to this campaign |
| MeshAgent | RMM (abused as C2) | Open-source MeshCentral agent; updated C2 server at `winmanage-me.network`; same operational role as June 2026 campaign but with fresh infrastructure |

---

## 4. Threat Actor / Campaign Attribution

| Field | Value |
|-------|-------|
| Actor | UNC6240 (ShinyHunters) |
| Type | Financially motivated cybercrime / data theft extortion |
| Activity Window | September 10–24, 2026 (renewed campaign) |
| Primary Targets | Higher Education, Technology, IT Services, Healthcare, Agriculture, Transportation, Government — **global scope** (not limited to US) |
| CVE Exploited | CVE-2026-35273 (Oracle PeopleSoft EMHub, CVSS 9.8, RCE, unauthenticated) via WAF bypass |
| Motive | Data theft and extortion; double extortion model (encrypt + publish) |
| Prior Campaign | May 27 – June 9, 2026 (C2: azurenetfiles.net, IPs: 142.11.200.186–190; see `2026-06-11_cloud-google-com-blog-topics-threat-intelligence-shinyhunters-oracle-peoplesoft-cve-2026-35273.md`) |

Organizations that patched CVE-2026-35273 remain protected; the vulnerability is the same. The renewed risk is specifically for organizations that:
1. **Applied WAF rules as a compensating control** without patching — the `%50SEMHUB` bypass circumvents literal-string WAF signatures
2. **Were patched but have incomplete web shell eviction** — web shells deployed during the June campaign may persist if cleanup was incomplete

---

## 5. Splunk Detection Searches

### 5a. WAF Bypass URI Pattern Detection
```spl
`web` (uri_path="/%50SEMHUB/*" OR uri_path="/%50SEMHUB/hub" OR uri_path="/%50SEMHUB/hub/*"
       OR uri_path="/%70semhub/*" OR uri_path="/%50semhub/*")
  AND method="POST"
| stats count min(_time) as firstTime max(_time) as lastTime
    values(src) as source_ips values(http_user_agent) as user_agents values(status) as statuses
    by dest uri_path
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=95
| table firstTime lastTime dest uri_path source_ips user_agents statuses count risk_score
```

### 5b. New JSP Web Shell Files in PSEMHUB.war Directory
```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Endpoint.Filesystem
where Filesystem.file_path="*PSEMHUB.war*"
  AND Filesystem.file_name IN ("x.jsp","u.jsp","u2.jsp","tunnel.jsp","tunnel.jspx","Ple64.exe")
by Filesystem.dest Filesystem.user Filesystem.file_path Filesystem.file_name Filesystem.action
| `drop_dm_object_name(Filesystem)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    file_name IN ("Ple64.exe"), 100,
    file_name IN ("tunnel.jsp","tunnel.jspx"), 98,
    file_name IN ("x.jsp","u.jsp","u2.jsp"), 95,
    1=1, 90)
| table firstTime lastTime dest user file_path file_name action risk_score
```

### 5c. Neo-reGeorg SOCKS5 Tunnel Traffic to Web Shell
```spl
`web` uri_path="*tunnel.jsp*" OR uri_path="*tunnel.jspx*"
| stats count min(_time) as firstTime max(_time) as lastTime
    values(src) as source_ips values(http_user_agent) as user_agents
    by dest uri_path method
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=95
| table firstTime lastTime dest uri_path method source_ips user_agents count risk_score
```

### 5d. SIDEEYE Backdoor C2 Network Connections
```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Network_Traffic.All_Traffic
where All_Traffic.dest="162.219.30.165"
  AND All_Traffic.dest_port IN (3333, 3334)
by All_Traffic.src All_Traffic.dest All_Traffic.dest_port All_Traffic.app All_Traffic.user
| `drop_dm_object_name(All_Traffic)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=98
| table firstTime lastTime src dest dest_port app user count risk_score
```

### 5e. MeshAgent Connecting to winmanage-me.network C2
```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Network_Traffic.All_Traffic
where All_Traffic.dest_host="winmanage-me.network"
by All_Traffic.src All_Traffic.dest All_Traffic.dest_port All_Traffic.app
| `drop_dm_object_name(All_Traffic)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=98
| table firstTime lastTime src dest dest_port app count risk_score
```

### 5f. Java/WebLogic Spawning Interactive Shell (Existing — still applicable)
```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Endpoint.Processes
where Processes.parent_process_name IN ("java", "java.exe")
  AND Processes.process_name IN ("cmd.exe","powershell.exe","bash","sh","curl","wget",
                                  "python","python3","sshpass","nc","perl","ruby","zstd")
by Processes.dest Processes.user Processes.parent_process_name
   Processes.process_name Processes.process Processes.process_id
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    process_name="sshpass", 92,
    process_name IN ("cmd.exe","powershell.exe") AND match(parent_process_name, "java"), 85,
    process_name IN ("curl","wget") AND match(parent_process_name, "java"), 75,
    1=1, 65)
| where risk_score >= 65
| table firstTime lastTime dest user parent_process_name process_name process risk_score
```

---

## 6. References

- [Google GTIG — ShinyHunters Renewed Mass Exploitation Campaign Targeting Oracle PeopleSoft (2026-09-25)](https://cloud.google.com/blog/topics/threat-intelligence/shinyhunters-renewed-mass-exploitation-campaign-targeting-oracle-peoplesoft)
- [Google GTIG — ShinyHunters Oracle PeopleSoft CVE-2026-35273 Original Campaign (2026-06-11)](https://cloud.google.com/blog/topics/threat-intelligence/shinyhunters-targets-education-sector-oracle-exploit)
- [Oracle Security Alert — CVE-2026-35273](https://www.oracle.com/security-alerts/alert-cve-2026-35273.html)
- [Neo-reGeorg SOCKS5 Tunnel — GitHub](https://github.com/L-codes/Neo-reGeorg)
- [MITRE ATT&CK — T1190: Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/)
- [MITRE ATT&CK — T1505.003: Server Software Component: Web Shell](https://attack.mitre.org/techniques/T1505/003/)
- [MITRE ATT&CK — T1027: Obfuscated Files or Information](https://attack.mitre.org/techniques/T1027/)
- [MITRE ATT&CK — T1219: Remote Access Software](https://attack.mitre.org/techniques/T1219/)
- [MITRE ATT&CK — UNC6240 (ShinyHunters) — G1060](https://attack.mitre.org/groups/G1060/)
