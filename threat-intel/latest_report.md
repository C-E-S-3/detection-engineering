---
scraped_at: 2025-04-03T16:00:00Z
source_url: https://cloud.google.com/blog/topics/threat-intelligence/china-nexus-exploiting-critical-ivanti-vulnerability
report_type: threat-intel
---

# Threat Intelligence Report: UNC5221 Exploitation of Ivanti Connect Secure (CVE-2025-22457)

## 1. Indicators of Compromise (IOCs)

### File Hashes
| Malware Family | MD5 Hash                             | File Name/Path                  | Description                       |
|----------------|--------------------------------------|----------------------------------|-----------------------------------|
| TRAILBLAZE     | 4628a501088c31f53b5c9ddf6788e835     | /tmp/.i                          | In-memory dropper                |
| BRUSHFIRE      | e5192258c27e712c7acf80303e68980b     | /tmp/.r                          | Passive backdoor                 |
| SPAWNSNARE     | 6e01ef1367ea81994578526b3bd331d6     | /bin/dsmain                      | Kernel extractor & encryptor      |
| SPAWNWAVE      | ce2b6a554ae46b5eb7d79ca5e7f440da     | /lib/libdsupgrade.so             | Implant utility                   |
| SPAWNSLOTH     | 10659b392e7f5b30b375b94cae4fdca0     | /tmp/.liblogblock.so             | Log tampering utility             |

### File Names and Paths
- /tmp/.i (TRAILBLAZE dropper)
- /tmp/.r (BRUSHFIRE backdoor)
- /bin/dsmain (SPAWNSNARE)
- /lib/libdsupgrade.so (SPAWNWAVE)
- /tmp/.liblogblock.so (SPAWNSLOTH)
- /tmp/.p (PID file for web process)
- /tmp/.m (memory map file)
- /tmp/.w (base address of web binary)
- /tmp/.s (base address of libssl.so)
- /data/var/cores (core dump directory)

### Domains and URLs
- No domains or URLs provided in the report.

### IP Addresses
- No IP addresses provided in the report.

### Registry Keys
- Not applicable (Linux/edge device context).

### Mutex Names
- Not provided.

### C2 Infrastructure Details
- The BRUSHFIRE backdoor is injected as an SSL_read hook, which may use TLS connections for C2, but no explicit C2 IPs/domains are given.
- UNC5221 leverages an obfuscation network of compromised Cyberoam appliances, QNAP devices, and ASUS routers to mask their true source.

### Email Addresses
- None provided.

---

## 2. TTPs (MITRE ATT&CK Mapping)

### Initial Access
- **T1190 - Exploit Public-Facing Application**
  - Exploitation of Ivanti Connect Secure VPN appliances via CVE-2025-22457 (buffer overflow, remote code execution).

### Execution
- **T1059.004 - Command and Scripting Interpreter: Unix Shell**
  - Use of shell scripts to deploy malware (TRAILBLAZE dropper).

- **T1106 - Native API**
  - TRAILBLAZE and BRUSHFIRE written in bare C, using raw syscalls for injection.

### Persistence
- **T1546.015 - Event Injection: Kernel Modules and Extensions**
  - SPAWNSNARE extracts and encrypts kernel images; SPAWNANT installs malware persistently.

- **T1037.001 - Boot or Logon Initialization Scripts: Unix**
  - SPAWNANT may drop webshells and modify initialization scripts for persistence.

### Defense Evasion
- **T1562.001 - Impair Defenses: Disable or Modify Syslog**
  - SPAWNSLOTH disables local logging and remote syslog forwarding.

- **T1564.006 - Hide Artifacts: Indicator Removal from Tools**
  - Deletion of temporary files and core dumps to evade detection.

- **T1027 - Obfuscated Files or Information**
  - Use of Base64 encoding for in-memory dropper; obfuscation network via compromised routers/appliances.

### Credential Access
- **T1552.001 - Unsecured Credentials: Credentials in Files**
  - Not explicitly mentioned, but possible via kernel image extraction.

### Collection
- **T1005 - Data from Local System**
  - SPAWNSNARE extracts kernel images.

### Exfiltration
- **T1041 - Exfiltration Over C2 Channel**
  - BRUSHFIRE backdoor sends data via SSL_write after executing shellcode.

### Impact
- **T1496 - Resource Hijacking**
  - Not directly mentioned, but killing child processes and tampering with logs may impact system resources.

---

## 3. Malware & Tools

### Malware Families
- **TRAILBLAZE**: In-memory dropper, written in C, uses raw syscalls, minimal footprint.
- **BRUSHFIRE**: Passive backdoor, SSL_read hook, executes shellcode, communicates via SSL_write.
- **SPAWNSNARE**: Kernel extractor/encryptor utility.
- **SPAWNWAVE**: Implant utility, evolved from SPAWNANT, overlaps with SPAWNCHIMERA and RESURGE.
- **SPAWNSLOTH**: Log tampering utility, disables logging and syslog forwarding.
- **SPAWNANT**: Installer for SPAWN family malware, drops webshells.

### Legitimate Tools Abused (LOLBins)
- **dslogserver**: Targeted for log tampering.
- **busybox**: Referenced in SPAWNSNARE YARA rule.

### Custom Tooling
- Shell script dropper for initial deployment.
- Modifications to Integrity Checker Tool (ICT) for detection evasion.

---

## 4. Threat Actor / Campaign Attribution

### Threat Actor
- **UNC5221**
  - Suspected China-nexus espionage actor.
  - History of zero-day exploitation of edge devices (Ivanti, NetScaler).
  - Aggressive operational tempo, sophisticated custom tooling.

### Campaigns
- Exploitation of CVE-2025-22457 (Ivanti Connect Secure).
- Prior campaigns: CVE-2025-0282, CVE-2023-46805, CVE-2024-21887, CVE-2023-4966.

### Motivations
- Espionage (targeting edge devices for persistent access).

### Targeted Sectors & Geographies
- Wide range of countries and verticals.
- Edge devices globally (VPNs, routers, appliances).

---

## 5. Splunk Detection Searches

### 5.1 File Hash Detection (Endpoint)
```spl
# Detect known malicious hashes on endpoints (Sysmon)
index=endpoint sourcetype=XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
| eval md5=lower(md5)
| search md5 IN ("4628a501088c31f53b5c9ddf6788e835", "e5192258c27e712c7acf80303e68980b", "6e01ef1367ea81994578526b3bd331d6", "ce2b6a554ae46b5eb7d79ca5e7f440da", "10659b392e7f5b30b375b94cae4fdca0")
| table _time, host, user, md5, Image, CommandLine
# Detects execution or presence of files matching known malware hashes.
```

### 5.2 Suspicious File Creation (Linux/Edge Device)
```spl
# Detect suspicious file creation in /tmp and /lib directories (Sysmon or Linux audit logs)
index=endpoint sourcetype=linux_audit OR sourcetype=XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
| search (file_path="/tmp/.i" OR file_path="/tmp/.r" OR file_path="/bin/dsmain" OR file_path="/lib/libdsupgrade.so" OR file_path="/tmp/.liblogblock.so")
| table _time, host, user, file_path, action
# Detects creation or modification of files associated with malware families.
```

### 5.3 Log Tampering Detection
```spl
# Detect disabling of syslog or tampering with dslogserver process (Sysmon or Linux audit logs)
index=endpoint sourcetype=linux_audit OR sourcetype=XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
| search (process_name="dslogserver" OR file_path="/tmp/.liblogblock.so")
| table _time, host, user, process_name, file_path, action
# Detects activity targeting log server processes or log tampering utilities.
```

### 5.4 Exploitation Attempt Detection (Network)
```spl
# Detect exploitation attempts against Ivanti Connect Secure VPN (firewall/proxy logs)
index=network sourcetype=firewall OR sourcetype=proxy
| search (dest_port=443 AND dest_ip IN (list_of_vpn_appliance_ips))
| stats count by src_ip, dest_ip, dest_port, uri_path, user_agent
| where count > threshold
# Detects anomalous access patterns to VPN appliances, possibly indicative of exploitation.
```

### 5.5 Core Dump and Anomaly Detection
```spl
# Detect creation of core dumps in /data/var/cores (Linux audit logs)
index=endpoint sourcetype=linux_audit
| search file_path="/data/var/cores"
| table _time, host, user, file_path, action
# Detects creation or deletion of core dumps, which may indicate post-exploitation activity.
```

### 5.6 TLS Certificate Anomaly Detection
```spl
# Detect anomalous client TLS certificates presented to VPN appliance (network logs)
index=network sourcetype=ssl
| stats count by src_ip, dest_ip, ssl_subject, ssl_issuer
| where ssl_subject matches suspicious pattern OR count > threshold
# Detects unusual client certificates, possibly used for C2 or lateral movement.
```

---

## 6. Executive Summary

UNC5221, a suspected China-nexus espionage actor, is actively exploiting a critical buffer overflow vulnerability (CVE-2025-22457) in Ivanti Connect Secure VPN appliances, enabling remote code execution and deployment of custom malware. The campaign leverages newly identified malware families (TRAILBLAZE, BRUSHFIRE) and the SPAWN ecosystem, employing sophisticated defense evasion and log tampering techniques. UNC5221's operations demonstrate a persistent focus on edge devices, using both zero-day and n-day vulnerabilities, and masking their activity through compromised routers and appliances. Immediate action is recommended: organizations should patch affected Ivanti appliances, monitor for IOCs and anomalous activity, and review logging and core dump files for signs of compromise. The urgency is high, as exploitation is ongoing and targets critical infrastructure globally.
