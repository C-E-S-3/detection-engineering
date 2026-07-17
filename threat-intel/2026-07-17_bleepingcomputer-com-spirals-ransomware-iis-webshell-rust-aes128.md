---
scraped_at: 2026-07-17T00:00:00Z
source_url: https://www.bleepingcomputer.com/news/security/new-spirals-ransomware-encrypts-victim-network-in-under-24-hours/
report_type: threat-intel
severity: high
title: "Spirals Ransomware: IIS Webshell Initial Access, WMI Lateral Movement, Rust AES-128 Full-Network Encryption in Under 24 Hours"
---

## 1. IOCs

No IOCs were released with primary source verification at time of ingestion. The BleepingComputer report describes the attack chain in detail but does not publish hashes, C2 domains, or IP addresses attributable to this specific actor. IOCs will be updated if released by the researching vendor.

## 2. TTPs

| Tactic | Technique ID | Technique Name | Usage |
|--------|-------------|----------------|-------|
| Initial Access | T1190 | Exploit Public-Facing Application | Internet-facing IIS server compromised; ASP.NET webshell deployed to gain initial foothold |
| Persistence | T1505.003 | Server Software Component: Web Shell | ASP.NET webshell installed on IIS server for persistent access; used to execute subsequent attack stages |
| Privilege Escalation | T1548.002 | Abuse Elevation Control Mechanism: Bypass User Account Control | UAC bypass performed after webshell access to obtain elevated local execution context |
| Persistence | T1136.001 | Create Account: Local Account | New local administrator account created to maintain access alongside webshell |
| Lateral Movement | T1021.001 | Remote Services: Remote Desktop Protocol | RDP enabled on compromised host; used for interactive lateral movement with freshly created local account |
| Credential Access | T1003.002 | OS Credential Dumping: Security Account Manager | SAM database dumped from compromised IIS host to obtain local account credential hashes |
| Credential Access | T1003.001 | OS Credential Dumping: LSASS Memory | LSASS memory dumped to extract cached credentials for lateral movement |
| Lateral Movement | T1047 | Windows Management Instrumentation | WMI used to propagate ransomware payload to 12 or more hosts simultaneously from the compromised IIS server |
| Defense Evasion | T1562.001 | Impair Defenses: Disable or Modify Tools | Security software removed from all compromised hosts prior to ransomware detonation |
| Command and Control | T1572 | Protocol Tunneling | revsocks and Chisel used to create encrypted tunnels for persistent C2 access; Cloudflare Tunnel also used |
| Command and Control | T1090.004 | Proxy: Domain Fronting | Cloudflare Tunnel used to front C2 traffic behind Cloudflare infrastructure, complicating detection and blocking |
| Defense Evasion | T1197 | BITS Jobs | bitsadmin.exe used to download ransomware payload masquerading as a legitimate BITS transfer |
| Impact | T1486 | Data Encrypted for Impact | Rust-based ransomware encrypts files using AES-128 with ECDH P-256 key exchange; intermittent encryption applied to files larger than 5 MB to maximize spread speed |

## 3. Malware & Tools

### Spirals Ransomware

A Rust-based ransomware binary that performs file encryption using AES-128 in combination with ECDH (Elliptic Curve Diffie-Hellman) P-256 for per-victim key encapsulation. The use of intermittent encryption — encrypting only portions of files larger than 5 MB — is a speed optimization increasingly common in modern ransomware families (Lockbit 3.0, ALPHV/BlackCat, and others use similar techniques). Files smaller than 5 MB receive full encryption. The ransom note is written to disk as `RECOVERY_SECTION.log`. No decryptor exists without the actor's ECDH private key.

The actor achieved full network encryption across an IT services firm's environment in South Asia in under 24 hours in June 2026, which is consistent with the WMI-based mass lateral movement to 12 or more hosts and the concurrent detonation pattern. Rust is increasingly preferred by ransomware operators for its cross-platform compilation capability, performance characteristics, and relative difficulty of analysis compared to interpreted languages.

### Tunneling Tools

The actor deployed multiple tunneling utilities to establish persistent C2 channels:

- **revsocks**: Open-source reverse SOCKS5 proxy; routes attacker traffic through the compromised host
- **Chisel**: Open-source TCP/UDP tunnel over HTTP using SSH for transport encryption
- **Cloudflare Tunnel (cloudflared)**: Used to front C2 endpoints behind Cloudflare infrastructure, making egress traffic appear to originate from legitimate Cloudflare IP ranges and complicating firewall-based blocking

### bitsadmin.exe Payload Delivery

The actor used bitsadmin.exe to download the ransomware payload to target hosts before execution. Invoking bitsadmin.exe for payload delivery is a living-off-the-land technique (T1197) that exploits the Windows Background Intelligent Transfer Service to transfer files in a manner that blends with legitimate Windows Update and software deployment traffic. When spawned from a webshell context (w3wp.exe → cmd.exe → bitsadmin.exe), this invocation pattern is anomalous.

## 4. Threat Actor / Campaign Attribution

**Actor:** Unknown; no attribution to a named threat group as of publication

**Target:** IT services firm, South Asia

**Date of attack:** June 2026

**Time to encryption:** Under 24 hours from initial IIS webshell access to full network encryption across 12+ hosts

**Notable characteristics:**
- Single-operator or small team based on the speed and coordination of the attack
- Use of multiple tunneling tools (revsocks, Chisel, Cloudflare Tunnel) suggests familiarity with network egress controls
- Rust ransomware with intermittent encryption optimized for speed over thoroughness
- No data exfiltration or double-extortion noted in the BleepingComputer report; encryption-only model
- Out-of-band extortion via `RECOVERY_SECTION.log` contact instructions
- The attack workflow (IIS webshell → credential dump → WMI spread → security removal → encrypt) is consistent with patterns observed in multiple 2025–2026 ransomware intrusions targeting organizations with internet-exposed legacy IIS servers

**Assessment:** The actor demonstrates operational competence in enterprise Windows environments — credential dumping, WMI lateral movement, tunneling tool deployment, and security software removal before encryption are all deliberate steps. The speed of execution (sub-24 hours) suggests either pre-existing reconnaissance or a well-rehearsed playbook. The target profile (IT services firm) is consistent with financially motivated ransomware operators seeking organizations that manage downstream client environments, multiplying extortion leverage.

## 5. Splunk Detection Searches

### Query 1: IIS Worker Process Spawning Command Shell (Webshell Execution)

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Endpoint.Processes
where Processes.parent_process_name="w3wp.exe"
  AND Processes.process_name IN ("cmd.exe", "powershell.exe", "powershell_ise.exe",
    "wscript.exe", "cscript.exe", "mshta.exe", "certutil.exe", "bitsadmin.exe",
    "curl.exe", "wget.exe", "whoami.exe", "net.exe", "net1.exe")
by Processes.dest Processes.user Processes.parent_process_name
   Processes.process_name Processes.process Processes.process_id
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=75
| table firstTime lastTime dest user parent_process_name process_name process risk_score
```

### Query 2: WMI Lateral Movement to Multiple Unique Hosts

```spl
| tstats `security_content_summariesonly` count dc(Processes.dest) as unique_dest_count
  min(_time) as firstTime max(_time) as lastTime
from datamodel=Endpoint.Processes
where Processes.process_name IN ("wmic.exe", "wmiprvse.exe")
  AND Processes.process IN ("*/node:*", "* /node:*", "*node:*")
by Processes.user Processes.process_name _time span=5m
| `drop_dm_object_name(Processes)`
| where unique_dest_count >= 5
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(unique_dest_count >= 12, 85, unique_dest_count >= 5, 65, 1=1, 50)
| where risk_score >= 65
| table firstTime lastTime user process_name unique_dest_count risk_score
```

### Query 3: RECOVERY_SECTION.log Ransom Note Creation

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Endpoint.Filesystem
where Filesystem.file_name="RECOVERY_SECTION.log"
by Filesystem.dest Filesystem.user Filesystem.file_path Filesystem.file_name Filesystem.process_name
| `drop_dm_object_name(Filesystem)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=100
| table firstTime lastTime dest user file_path file_name process_name risk_score
```

### Query 4: bitsadmin.exe Transfer Spawned from Web or Shell Context

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Endpoint.Processes
where Processes.process_name="bitsadmin.exe"
  AND (Processes.process IN ("*/transfer*", "*/addfile*", "*/download*", "*/create*")
    OR Processes.process IN ("*http://*", "*https://*"))
  AND Processes.parent_process_name IN ("cmd.exe", "powershell.exe", "w3wp.exe",
    "wscript.exe", "cscript.exe")
by Processes.dest Processes.user Processes.parent_process_name
   Processes.process_name Processes.process Processes.process_id
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    match(parent_process_name, "(?i)w3wp"), 85,
    1=1, 65)
| where risk_score >= 65
| table firstTime lastTime dest user parent_process_name process_name process risk_score
```

## 6. Executive Summary

In July 2026, BleepingComputer reported on Spirals ransomware, a Rust-based ransomware used in a June 2026 attack against an IT services firm in South Asia. The actor gained initial access by deploying an ASP.NET webshell on an internet-facing IIS server, then escalated privileges via UAC bypass, created a local administrator account, enabled RDP, and dumped SAM and LSASS credentials. Using those credentials, the actor deployed revsocks, Chisel, and Cloudflare Tunnel for persistent C2, then used WMI to push the ransomware payload to 12 or more hosts simultaneously. Before triggering encryption, the actor removed security software from all compromised hosts. The Rust-based Spirals ransomware uses AES-128 encryption with ECDH P-256 key exchange and applies intermittent encryption to files larger than 5 MB for speed. Full network encryption was achieved in under 24 hours. The ransom note is written as `RECOVERY_SECTION.log`. No C2 domains, IPs, or file hashes were released at time of publication. No attribution to a named threat actor has been made. Detection focus should be on the IIS webshell execution pattern (w3wp.exe spawning cmd.exe/PowerShell), high-volume WMI lateral movement (≥5 remote hosts in a 5-minute window), and RECOVERY_SECTION.log filesystem creation.

## References

- [BleepingComputer — New Spirals Ransomware Encrypts Victim Network in Under 24 Hours (2026-07-17)](https://www.bleepingcomputer.com/news/security/new-spirals-ransomware-encrypts-victim-network-in-under-24-hours/)
- [MITRE ATT&CK — T1190: Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/)
- [MITRE ATT&CK — T1505.003: Web Shell](https://attack.mitre.org/techniques/T1505/003/)
- [MITRE ATT&CK — T1047: Windows Management Instrumentation](https://attack.mitre.org/techniques/T1047/)
- [MITRE ATT&CK — T1486: Data Encrypted for Impact](https://attack.mitre.org/techniques/T1486/)
- [MITRE ATT&CK — T1197: BITS Jobs](https://attack.mitre.org/techniques/T1197/)
- [MITRE ATT&CK — T1572: Protocol Tunneling](https://attack.mitre.org/techniques/T1572/)
