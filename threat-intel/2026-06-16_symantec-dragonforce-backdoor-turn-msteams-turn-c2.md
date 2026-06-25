---
scraped_at: "2026-06-17T00:00:00Z"
source_url: "https://www.security.com/threat-intelligence/dragonforce-msteams-backdoor"
report_type: threat-intel
severity: critical
title: "DragonForce Backdoor.Turn: First In-the-Wild Ransomware C2 Hidden in Microsoft Teams TURN Relay Infrastructure"
---

## 1. IOCs

No traditional network IOCs are actionable for this campaign. Backdoor.Turn routes all C2 traffic through **legitimate Microsoft Teams TURN relay servers**, making IP and domain blocking infeasible without impacting legitimate Microsoft services.

**Host-Based Indicators:**
- Process injection target: `DbgView64.exe` (Sysinternals DebugView 64-bit) used as a host process for Backdoor.Turn; this binary running with anomalous network behavior or as an unexpected parent is suspicious
- Malware is Go-compiled; look for unsigned Go binaries in unusual paths
- Backdoor.Turn obtains an anonymous Teams visitor token at runtime from Microsoft Skype/Teams identity services

**No confirmed file hashes** were available from public sources at time of report. Full IOC list published by Symantec in the original advisory.

## 2. TTPs (MITRE ATT&CK)

| Tactic | Technique | ID | Usage |
|--------|-----------|-----|-------|
| Command and Control | Proxy: External Proxy | T1090.002 | C2 traffic tunneled through Microsoft Teams TURN relay; attacker's real C2 server is obscured behind legitimate Microsoft infrastructure |
| Command and Control | Application Layer Protocol: Web Protocols | T1071.001 | QUIC session established through TURN relay to attacker C2; outbound traffic appears as legitimate Teams relay communication |
| Command and Control | Web Service | T1102 | Anonymous Teams visitor token acquired from Microsoft identity API to authenticate to TURN relay as a legitimate Teams client |
| Defense Evasion | Masquerading | T1036 | C2 traffic indistinguishable from legitimate Microsoft Teams relay connections; all outbound connections terminate at Microsoft-owned infrastructure |
| Defense Evasion | Impair Defenses | T1562 | TURN relay tunneling defeats firewall rules that trust Microsoft infrastructure; network monitoring tools see only legitimate Microsoft relay IPs |
| Execution | Process Injection | T1055 | Backdoor.Turn injected into `DbgView64.exe` (Sysinternals DebugView 64-bit) for stealth and persistence in memory |
| Discovery | Account Discovery: Domain Account | T1087.002 | LDAP queries for Active Directory account enumeration |
| Discovery | Network Service Discovery | T1046 | Internal network scanning for lateral movement target identification |
| Credential Access | Credentials from Web Browsers | T1555.003 | Browser credential theft capability |
| Lateral Movement | (via credential and AD data harvested) | | AD enumeration and credential-based lateral movement |
| Impact | Data Encrypted for Impact | T1486 | DragonForce RaaS ransomware deployed as final stage after dwell period |

## 3. Malware & Tools

**Backdoor.Turn**
- **Type:** Custom Go-based remote access trojan (RAT)
- **C2 mechanism:** Anonymous Microsoft Teams TURN relay — first documented in-the-wild abuse of Teams TURN infrastructure for malware C2
- **Execution:** Process injection into `DbgView64.exe` (Sysinternals DebugView 64-bit binary)
- **Transport:** QUIC protocol session tunneled through legitimate Microsoft TURN relay servers
- **Authentication evasion:** Acquires anonymous visitor token from Microsoft/Skype identity services to appear as a legitimate Teams client to the TURN relay
- **Capabilities:**
  - Remote command execution
  - Active Directory enumeration (LDAP)
  - Internal network scanning
  - TLS certificate collection
  - Browser credential theft
  - Credential-based lateral movement

## 4. Threat Actor / Campaign Attribution

**DragonForce Ransomware Group**
- **Type:** Ransomware-as-a-Service (RaaS) operation
- **Active since:** 2023
- **Model:** Provides affiliates with ransomware tools and supporting infrastructure in exchange for a share of ransom payments
- **Confirmed victim:** Major U.S. services company (sector not publicly specified)
- **Dwell time:** Approximately 2 months (intrusion began December 2025; detected approximately February 2026)
- **Discovery:** Symantec Threat Hunter Team, published June 16, 2026

## 5. Splunk Detection Searches

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Processes
  where Processes.process_name="DbgView64.exe"
    AND (Processes.parent_process_name!="DbgView.exe"
         AND Processes.parent_process_name!="explorer.exe"
         AND Processes.parent_process_name!="cmd.exe"
         AND Processes.parent_process_name!="powershell.exe")
  by Processes.dest Processes.user Processes.parent_process_name
     Processes.process_name Processes.process Processes.process_id
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=85
| table firstTime lastTime dest user parent_process_name process_name process risk_score
```

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Network_Traffic.All_Traffic
  where All_Traffic.app="quic" OR All_Traffic.dest_port=3478 OR All_Traffic.dest_port=5349
  by All_Traffic.src All_Traffic.dest All_Traffic.dest_port All_Traffic.app
     All_Traffic.process_name
| `drop_dm_object_name(All_Traffic)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| where NOT match(process_name, "(?i)(teams|msedge|chrome|firefox|outlook|lync|skype)")
| eval risk_score=case(
    process_name="DbgView64.exe", 95,
    match(process_name, "(?i)(svchost|lsass|winlogon|csrss)"), 90,
    1=1, 70)
| where risk_score >= 70
| table firstTime lastTime src dest dest_port process_name app risk_score
```

```spl
index=proxy OR index=firewall
  (dest_host="*.turn.skype.com" OR dest_host="*.relay.teams.microsoft.com"
   OR dest_host="*.teams.microsoft.com")
  AND (protocol="quic" OR dest_port=3478 OR dest_port=5349)
| eval process_lower=lower(process)
| where NOT match(process_lower, "teams|msedge|chrome|firefox|outlook|lync|skype")
| stats count min(_time) as firstTime max(_time) as lastTime by src dest dest_host dest_port process
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(match(process, "(?i)dbgview"), 95, 1=1, 75)
| where risk_score >= 75
| table firstTime lastTime src dest dest_host dest_port process risk_score
```

```spl
`crowdstrike`
  event_simpleName=ProcessRollup2
  FileName="DbgView64.exe"
| eval suspicious=if(match(ParentBaseFileName, "(?i)(teams|explorer|cmd|powershell)"), 0, 1)
| where suspicious=1
| stats count min(timestamp) as firstTime max(timestamp) as lastTime
  by ComputerName UserName ParentBaseFileName FileName CommandLine
| eval risk_score=85
| table firstTime lastTime ComputerName UserName ParentBaseFileName FileName CommandLine risk_score
```

## 6. Executive Summary

On June 16, 2026, Symantec disclosed that the **DragonForce ransomware group** deployed a novel backdoor called **Backdoor.Turn** during a two-month intrusion at a major U.S. services company. This represents the **first documented in-the-wild abuse of Microsoft Teams TURN relay infrastructure for malware command and control**.

The attack's core evasion relies on the legitimate Microsoft Teams protocol stack: Backdoor.Turn acquires an anonymous visitor token from Microsoft's Skype-backed identity services, uses it to authenticate to a real Microsoft TURN relay server, and then establishes a QUIC session through that relay to the attacker's actual C2 server. From a network monitoring perspective, all outbound connections terminate at legitimate Microsoft infrastructure — making this technique exceptionally difficult to detect via traditional network IOC blocking or domain reputation.

The RAT is injected into `DbgView64.exe` (Sysinternals DebugView), a signed, legitimate Microsoft tool commonly allowlisted by security tools. Capabilities include full remote command execution, Active Directory enumeration via LDAP, internal network scanning, TLS certificate collection, browser credential theft, and credential-based lateral movement — everything an affiliate needs to stage a full DragonForce ransomware deployment.

**Key detection angles:**
1. `DbgView64.exe` running from an unexpected parent process or exhibiting outbound QUIC/TURN connections
2. Non-Teams processes (especially Sysinternals tools) connecting to `*.turn.skype.com` or `*.relay.teams.microsoft.com` on TURN ports (3478/5349)
3. Anonymous Teams visitor token requests from non-Teams processes in proxy/HTTP logs

## References

- [Symantec — Hidden in Teams: DragonForce Backdoor.Turn (2026-06-16)](https://www.security.com/threat-intelligence/dragonforce-msteams-backdoor)
- [BleepingComputer — Ransomware Gang Abuses Microsoft Teams Relays (2026-06-16)](https://www.bleepingcomputer.com/news/security/ransomware-gang-abuses-microsoft-teams-relays-to-hide-malicious-traffic/)
- [Help Net Security — DragonForce Microsoft Teams Malware (2026-06-16)](https://www.helpnetsecurity.com/2026/06/16/dragonforce-microsoft-teams-malware-backdoor-turn/)
- [MITRE ATT&CK — T1090.002: Proxy: External Proxy](https://attack.mitre.org/techniques/T1090/002/)
- [MITRE ATT&CK — T1102: Web Service](https://attack.mitre.org/techniques/T1102/)
- [MITRE ATT&CK — T1055: Process Injection](https://attack.mitre.org/techniques/T1055/)
- [MITRE ATT&CK — G1075: DragonForce](https://attack.mitre.org/groups/G1075/)
