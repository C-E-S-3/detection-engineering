---
scraped_at: 2026-06-07T00:00:00Z
source_url: https://www.volexity.com/blog/2026/06/04/verdantbamboo-just-another-brickstorm-in-the-firewall/
report_type: threat-intel
severity: critical
title: "VerdantBamboo (UNC5221/WARP PANDA): BRICKSTORM Evolves with PLENET and AgentPSD for 18-Month Dwell-Time Espionage"
---

# VerdantBamboo (UNC5221/WARP PANDA): BRICKSTORM Evolves with PLENET and AgentPSD for 18-Month Dwell-Time Espionage

On June 4, 2026, Volexity published a detailed investigation revealing that the Chinese nation-state threat actor VerdantBamboo (also tracked as UNC5221 by Mandiant and WARP PANDA by CrowdStrike) has significantly expanded its malware arsenal beyond the previously known BRICKSTORM backdoor. Two previously undocumented malware families — **PLENET** and **AgentPSD** — were observed deployed during an intrusion with an 18-month dwell time that also compromised the victim organization's managed services provider (MSP).

## 1. IOCs

No specific network IOCs (domains, IP addresses) are available for this campaign. VerdantBamboo took the associated C2 infrastructure offline before Volexity could complete infrastructure enumeration — the researchers built a fingerprint to identify BRICKSTORM C2 candidates but the threat actor rotated infrastructure prior to confirmation.

**File-Based Behavioral Indicators:**

| Indicator Type | Description |
|---------------|-------------|
| Process | `python3` or `python` spawned from a web server or system daemon on Linux (AgentPSD reverse shell indicator) |
| Process | Native AOT EXE/DLL in unusual paths on Windows servers (`%TEMP%`, `%AppData%`, user profile directories) representing PLENET |
| Module Load | .NET Native AOT compiled assemblies (no .NET runtime loaded; standalone native PE with non-standard import tables) |
| Network | Outbound TCP connections from Python processes on Linux servers to non-standard ports |

## 2. TTPs (MITRE ATT&CK)

| Tactic | Technique ID | Technique Name | Description |
|--------|-------------|----------------|-------------|
| Initial Access | T1190 | Exploit Public-Facing Application | Initial access via edge network appliances (NAS devices, firewalls) using BRICKSTORM implanted in firmware or running processes |
| Persistence | T1505.003 | Server Software Component: Web Shell | PLENET deployed as a persistent module within web server infrastructure on Windows systems; provides remote code execution, file operations, and C2 switching |
| Persistence | T1078.003 | Valid Accounts: Local Accounts | Use of stolen or harvested local credentials to persist lateral movement pathways through MSP-connected environments |
| Defense Evasion | T1027.007 | Obfuscated Files or Information: Dynamic API Resolution | PLENET compiled with .NET 7+ Native AOT, producing a standalone native binary with no .NET runtime dependency — defeats .NET-specific detection logic and AMSI hooks |
| Defense Evasion | T1036.005 | Masquerading: Match Legitimate Name or Location | AgentPSD deployed with innocuous filenames to blend into legitimate Python-heavy environments or system directories |
| Lateral Movement | T1090.001 | Proxy: Internal Proxy | BRICKSTORM on compromised edge appliances used as internal SOCKS5 proxy to relay attacker traffic through the victim network without direct external exposure |
| Command and Control | T1071.001 | Application Layer Protocol: Web Protocols | PLENET uses encrypted HTTP(S) for C2 communication, with configurable C2 server switching to maintain access |
| Command and Control | T1095 | Non-Application Layer Protocol | AgentPSD Python reverse shell communicates over raw TCP socket to attacker-controlled listener |
| Collection | T1213 | Data from Information Repositories | Threat actor accessed sensitive databases containing corporate, legal, and government information |

## 3. Malware & Tools

| Malware | Language | Platform | Capabilities | Notes |
|---------|----------|----------|--------------|-------|
| BRICKSTORM | Go / Rust (variants) | Linux (edge appliances: NAS, firewall firmware) | SOCKS5 proxy relay, C2 staging, persistence across reboots, bidirectional tunneling | Previously documented; Volexity first reported in 2024; Mandiant documented again September 2025 |
| PLENET (also tracked as "Grimbolt" by Google GTIG) | .NET Core, compiled via Native AOT | Windows | Remote command execution, interactive shell access, file manipulation (read/write/delete), C2 server switching, .NET assembly loading | New; Native AOT compilation bypasses .NET-specific detections and AMSI; deployed on internal Windows servers post-lateral movement |
| AgentPSD | Python | Linux | Python-based reverse shell used as fallback persistence; connects outbound to attacker-controlled TCP listener; provides interactive command execution | New; deployed as a secondary persistence mechanism if primary implants are removed; targets Linux servers in victim environment |

**Pivot Chain:**
1. Edge appliance (NAS/firewall) compromised with BRICKSTORM
2. BRICKSTORM used as SOCKS5 relay to pivot into internal network
3. PLENET deployed on Windows servers for primary interactive access
4. AgentPSD deployed on Linux servers as fallback persistence

## 4. Threat Actor / Campaign Attribution

| Attribute | Detail |
|-----------|--------|
| Actor Names | VerdantBamboo (Volexity), UNC5221 (Mandiant/Google GTIG), WARP PANDA (CrowdStrike) |
| Nexus | People's Republic of China (PRC); espionage mission |
| Active Since | At least 2023 (BRICKSTORM first observed) |
| Dwell Time | 18+ months confirmed in at least one investigated intrusion |
| MSP Compromise | Yes — threat actor also compromised the victim's managed services provider, enabling access to multiple downstream organizations |
| Target Sectors | Technology companies, legal services, software-as-a-service providers, business process outsourcers |
| Primary Geography | United States |
| Prior Reporting | Mandiant (September 2025): BRICKSTORM used against legal and technology sectors; earlier (April 2024) documented Ivanti Connect Secure exploitation (CVE-2023-46805 / CVE-2024-21887) |

## 5. Splunk Detection Searches

```spl
| comment "AgentPSD: Python process spawned from non-interactive parent on Linux — reverse shell indicator"
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Processes
  where Processes.process_name IN ("python", "python3", "python2", "python2.7")
    AND NOT Processes.parent_process_name IN
      ("bash", "sh", "dash", "zsh", "cron", "crond", "systemd", "init",
       "sshd", "ansible", "puppet", "chef-client", "salt-minion", "supervisord",
       "jenkins", "gitlab-runner", "celery", "gunicorn", "uwsgi")
  by Processes.dest Processes.user Processes.parent_process_name Processes.process_name
     Processes.process Processes.process_id
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    parent_process_name IN ("apache2", "nginx", "httpd", "w3wp.exe", "php", "php-fpm"), 95,
    match(process, "(?i)(socket|connect|recv|bind|listen|reverse|shell)"), 90,
    match(process, "(?i)(-c\s+import|exec\(|__import__)"), 90,
    parent_process_name IN ("cron", "at", "atd"), 75,
    1=1, 60)
| where risk_score >= 60
| table firstTime lastTime dest user parent_process_name process_name process process_id risk_score
```

```spl
| comment "PLENET: IIS worker (w3wp.exe) spawning anomalous child processes — in-memory web shell / Native AOT module indicator"
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Processes
  where Processes.parent_process_name="w3wp.exe"
    AND Processes.process_name IN
      ("cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe",
       "mshta.exe", "rundll32.exe", "regsvr32.exe", "certutil.exe",
       "bitsadmin.exe", "curl.exe", "wget.exe", "whoami.exe")
  by Processes.dest Processes.user Processes.parent_process_name Processes.process_name
     Processes.process Processes.process_id
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    process_name IN ("powershell.exe", "cmd.exe"), 90,
    process_name IN ("certutil.exe", "bitsadmin.exe", "curl.exe", "wget.exe"), 85,
    process_name IN ("rundll32.exe", "regsvr32.exe", "mshta.exe"), 90,
    1=1, 75)
| where risk_score >= 75
| table firstTime lastTime dest user parent_process_name process_name process process_id risk_score
```

```spl
| comment "BRICKSTORM internal proxy relay: edge appliance outbound HTTPS on non-standard ports — SOCKS5 tunneling indicator"
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Network_Traffic.All_Traffic
  where All_Traffic.dest_port IN (443, 4443, 8443, 8080, 8888, 9443, 10443)
    AND All_Traffic.src_category IN ("network_appliance", "firewall", "vpn", "storage")
  by All_Traffic.src All_Traffic.src_category All_Traffic.dest All_Traffic.dest_port
     All_Traffic.bytes_out All_Traffic.bytes_in
| `drop_dm_object_name(All_Traffic)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    bytes_out > 50000000, 85,
    dest_port IN (4443, 8443, 9443, 10443), 75,
    1=1, 60)
| where risk_score >= 60
| table firstTime lastTime src src_category dest dest_port bytes_in bytes_out risk_score
```

## 6. Executive Summary

On June 4, 2026, Volexity published findings from an intrusion response engagement revealing that VerdantBamboo (UNC5221/WARP PANDA), a Chinese nation-state espionage group, has substantially evolved its toolkit beyond the previously documented BRICKSTORM edge appliance backdoor.

The investigation uncovered an 18-month dwell-time intrusion in which VerdantBamboo maintained persistent access across both the primary victim and the victim's managed services provider (MSP). The threat actor's initial foothold — via BRICKSTORM planted on a network-edge appliance — went undetected for over a year, during which time they pivoted laterally and deployed two previously undocumented malware families:

- **PLENET** (tracked as "Grimbolt" by Google GTIG): A .NET Core backdoor compiled with Native AOT, producing a standalone native binary that bypasses AMSI hooks and .NET-specific detection. PLENET provides interactive shell access, remote command execution, file manipulation, and the ability to switch C2 servers — indicating a focus on operational resilience and persistence even if individual C2 endpoints are burned.

- **AgentPSD**: A Python-based reverse shell utility deployed on Linux systems as a fallback persistence mechanism. If primary implants (BRICKSTORM, PLENET) are removed, AgentPSD provides the attacker continued interactive access via an outbound TCP connection to an attacker-controlled listener.

The MSP compromise is particularly significant: by compromising the service provider, VerdantBamboo potentially gained downstream access to multiple customer networks from a single foothold, consistent with known Chinese espionage targeting of IT supply chains.

Defenders should audit edge appliances for unexpected outbound connections, enforce process-lineage policies that alert on Python or shell processes spawned from web servers, and prioritize detection of .NET Native AOT DLLs loading from user-writable paths. Organizations using MSPs should require MFA and segmentation between MSP management channels and internal networks.

## References

- [Volexity — VerdantBamboo: Just Another BRICKSTORM in the Firewall (2026-06-04)](https://www.volexity.com/blog/2026/06/04/verdantbamboo-just-another-brickstorm-in-the-firewall/)
- [BleepingComputer — Chinese APT deploys new malware to keep access to hacked networks (2026-06-05)](https://www.bleepingcomputer.com/news/security/chinese-apt-deploys-new-malware-to-keep-access-to-hacked-networks/)
- [Google GTIG — Another BRICKSTORM: Stealthy Backdoor Enabling Espionage into Tech and Legal Sectors (2026-03-26)](https://cloud.google.com/blog/topics/threat-intelligence/brickstorm-espionage-campaign)
- [Mandiant — UNC5221 Uses BRICKSTORM Backdoor (2025-09)](https://thehackernews.com/2025/09/unc5221-uses-brickstorm-backdoor-to.html)
- [MITRE ATT&CK — UNC5221 / VerdantBamboo](https://attack.mitre.org/)
- [MITRE ATT&CK — T1190: Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/)
- [MITRE ATT&CK — T1505.003: Web Shell](https://attack.mitre.org/techniques/T1505/003/)
- [MITRE ATT&CK — T1090.001: Internal Proxy](https://attack.mitre.org/techniques/T1090/001/)
