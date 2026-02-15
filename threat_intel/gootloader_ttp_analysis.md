# Gootloader Malware - TTPs and Analysis

## Overview

Gootloader (also tracked as GootLoader) is a JavaScript-based malware loader that has been active since at least 2020 and serves as an initial access broker for follow-on payloads including Cobalt Strike, REvil/Sodinokibi ransomware, Kronos trojan, SystemBC, and IcedID. It is attributed to the threat group tracked as UNC2565 (Mandiant) and is notable for its heavy use of SEO poisoning to deliver malicious JavaScript payloads through compromised legitimate websites.

---

## Kill Chain and Tactics, Techniques, and Procedures (TTPs)

### Stage 1: Initial Access - SEO Poisoning and Malicious Downloads

**MITRE ATT&CK:**
- T1189 - Drive-by Compromise
- T1608.006 - Stage Capabilities: SEO Poisoning
- T1204.002 - User Execution: Malicious File

**Description:**
Gootloader operators compromise legitimate WordPress websites and inject pages designed to rank highly in search engine results for targeted keywords. Common lure topics include legal documents, contracts, agreements, and business templates (e.g., "free non-disclosure agreement template", "real estate purchase agreement form"). When a victim clicks on a poisoned search result, the compromised site presents a fake forum page with a download link. The downloaded file is a ZIP archive containing a single obfuscated JavaScript (.js) file. The JS filename is crafted to match the victim's search query to increase the likelihood of execution.

**Key Indicators:**
- ZIP files downloaded from compromised WordPress sites
- ZIP archive contains a single `.js` file
- JavaScript file size is typically 40 KB or larger due to obfuscation padding
- Filename matches the search query used to find the site (e.g., `free_employee_non_compete_agreement_12345.js`)

---

### Stage 2: Execution - JavaScript Payload via Wscript

**MITRE ATT&CK:**
- T1059.007 - Command and Scripting Interpreter: JavaScript
- T1027 - Obfuscated Files or Information
- T1027.010 - Obfuscated Files or Information: Command Obfuscation

**Description:**
The victim double-clicks the `.js` file, which is executed by `wscript.exe` (Windows Script Host). The JavaScript is heavily obfuscated using variable name randomization, string concatenation, junk code insertion, and multi-layer encoding. Upon execution, the script performs the following actions:
1. Assembles a second-stage payload from string fragments scattered throughout the file
2. Writes encoded data to the Windows Registry for persistence and staging
3. Creates a scheduled task to ensure persistence
4. Spawns PowerShell to decode and execute the next stage

**Key Indicators:**
- `wscript.exe` executing a `.js` file from `Downloads`, `Desktop`, or `Temp` directories
- `wscript.exe` spawning `powershell.exe` or `cscript.exe` (abnormal parent-child relationship)
- Large `.js` file with excessive obfuscation

---

### Stage 3: Persistence - Scheduled Tasks and Registry Stuffing

**MITRE ATT&CK:**
- T1053.005 - Scheduled Task/Job: Scheduled Task
- T1112 - Modify Registry
- T1574.011 - Hijack Execution Flow: Services Registry Permissions Weakness

**Description:**
Gootloader achieves persistence through two primary methods:

**Registry Stuffing:** The malware writes large base64-encoded or custom-encoded payload blobs into the Windows Registry, typically under `HKEY_CURRENT_USER\SOFTWARE\<random_name>`. These registry values contain the encoded second and third stage payloads. This technique avoids writing payloads to disk, making file-based detection difficult.

**Scheduled Tasks:** Gootloader creates scheduled tasks that execute on user logon or at regular intervals. The task typically invokes `wscript.exe` or `cscript.exe` to re-run a JavaScript file, or directly invokes PowerShell with an encoded command that reads the payload from the registry.

**Key Indicators:**
- `schtasks.exe /create` with references to `wscript`, `cscript`, or PowerShell
- Large registry writes to `HKCU\SOFTWARE\*` by `wscript.exe` or `powershell.exe`
- Scheduled tasks referencing `.js` files in user-writable directories
- Registry values containing abnormally large data blobs

---

### Stage 4: Defense Evasion - Fileless Execution and Obfuscation

**MITRE ATT&CK:**
- T1027 - Obfuscated Files or Information
- T1140 - Deobfuscate/Decode Files or Information
- T1218 - System Binary Proxy Execution
- T1059.001 - Command and Scripting Interpreter: PowerShell

**Description:**
Gootloader employs multiple defense evasion techniques:

**Fileless Execution:** After initial access, subsequent stages are decoded from the registry and executed directly in memory by PowerShell, avoiding disk writes that would trigger traditional antivirus.

**Multi-Layer Obfuscation:** The initial JavaScript uses extensive obfuscation. The PowerShell stage uses base64 encoding, string reversal, character substitution, and variable-based assembly to reconstruct commands.

**Living Off The Land:** All execution relies on native Windows binaries (`wscript.exe`, `cscript.exe`, `powershell.exe`, `schtasks.exe`) to avoid deploying custom executables.

**Key Indicators:**
- PowerShell commands referencing registry paths combined with `FromBase64String`, `[System.Convert]`, or `Invoke-Expression`
- Extremely long PowerShell command lines (1000+ characters)
- PowerShell using `-WindowStyle Hidden`, `-NoProfile`, and `-EncodedCommand` together
- No malicious executables dropped to disk

---

### Stage 5: Command and Control - HTTPS to Compromised Websites

**MITRE ATT&CK:**
- T1071.001 - Application Layer Protocol: Web Protocols
- T1573.002 - Encrypted Channel: Asymmetric Cryptography
- T1104 - Multi-Stage Channels

**Description:**
Gootloader communicates with C2 infrastructure over HTTPS to blend in with normal web traffic. The C2 servers are frequently compromised WordPress websites, which makes blocklisting based on domain reputation difficult since these are otherwise legitimate domains. Communication patterns include:

1. Initial check-in with system information (hostname, username, domain, OS version)
2. Retrieval of additional payloads from the C2
3. Periodic beaconing at semi-regular intervals

The malware typically sends HTTP POST requests to WordPress-specific URI paths such as `/wp-content/uploads/`, `/wp-includes/`, or `/wp-admin/admin-ajax.php` on the compromised sites.

**Key Indicators:**
- Non-browser processes making HTTP POST requests to WordPress URI paths
- Outbound HTTPS connections to multiple distinct external domains from a single host
- Beaconing patterns with low jitter (regular intervals)
- User-Agent strings associated with scripting engines rather than browsers

---

### Stage 6: Payload Delivery - Loading Follow-On Malware

**MITRE ATT&CK:**
- T1105 - Ingress Tool Transfer
- T1055 - Process Injection

**Description:**
The ultimate objective of Gootloader is to deliver additional malware payloads. Observed follow-on payloads include:

| Payload | Type | Purpose |
|---------|------|---------|
| Cobalt Strike | C2 Framework | Post-exploitation, lateral movement |
| REvil / Sodinokibi | Ransomware | Data encryption and extortion |
| Kronos / Osiris | Banking Trojan | Credential theft |
| SystemBC | Proxy/Backdoor | SOCKS5 proxy for C2 tunneling |
| IcedID | Loader/Trojan | Additional malware delivery |
| Gootkit | Infostealer | Browser data and credential theft |

The follow-on payload is typically injected into a legitimate process or executed via reflective loading in the PowerShell process.

---

## Typical Attack Flow Diagram

```
1. Victim searches Google for a legal/business document
                    |
2. Clicks poisoned search result leading to compromised WordPress site
                    |
3. Fake forum page presents download link
                    |
4. ZIP archive downloaded (contains obfuscated .js file)
                    |
5. Victim executes .js file -> wscript.exe launches
                    |
6. wscript.exe writes encoded payloads to HKCU\SOFTWARE registry
                    |
7. wscript.exe creates scheduled task for persistence
                    |
8. wscript.exe spawns powershell.exe
                    |
9. PowerShell reads, decodes, and executes payload from registry
                    |
10. PowerShell beacons to compromised WordPress C2 over HTTPS
                    |
11. Follow-on payload delivered (Cobalt Strike, ransomware, etc.)
```

---

## Hunting Recommendations

1. **Process Lineage:** Hunt for `wscript.exe` spawning `powershell.exe` or `cscript.exe`. This parent-child relationship is rarely legitimate.

2. **Registry Monitoring:** Monitor for large writes to `HKCU\SOFTWARE\*` by script interpreters. Registry values exceeding typical sizes (multiple KB) should be investigated.

3. **Scheduled Task Auditing:** Review newly created scheduled tasks that reference `wscript.exe`, `cscript.exe`, `.js` files, or PowerShell with encoded commands.

4. **JavaScript File Creation:** Monitor for `.js` file creation in user directories (`Downloads`, `Desktop`, `Temp`), particularly files that are unusually large.

5. **PowerShell Command Length:** Alert on PowerShell process creation with command lines exceeding 1000 characters, especially when the parent process is `wscript.exe`.

6. **Network Analysis:** Inspect non-browser HTTP POST traffic to WordPress paths. Correlate outbound connections with known Gootloader IOC feeds.

7. **DNS Anomalies:** Look for hosts resolving an unusual number of unique domains in short time windows, particularly domains with high entropy or unusual naming patterns.

---

## References

- MITRE ATT&CK Group: UNC2565
- MITRE ATT&CK Software: Gootloader (S1138)
- Mandiant: Tracking and Disrupting GootLoader Operations
- HP Wolf Security: Gootloader Deep-Dive Analysis
- CISA Advisory: Known Exploited Vulnerabilities and Initial Access Broker TTPs
