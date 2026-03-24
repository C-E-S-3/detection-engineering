---
scraped_at: 2024-06-10T15:00:00Z
source_url: https://cloud.google.com/blog/topics/threat-intelligence/unc6201-exploiting-dell-recoverpoint-zero-day
report_type: threat-intel
---

# Threat Intelligence Report: UNC6201 Exploiting Dell RecoverPoint Zero-Day

## 1. Indicators of Compromise (IOCs)

### IP Addresses
- **149.248.11.71** (GRIMBOLT C2)

### Domains and URLs
- **wss://149.248.11.71/rest/apisession** (GRIMBOLT C2 endpoint)

### File Hashes (SHA256)
| Malware Family | File Name         | SHA256                                                         |
| -------------- | ----------------- | -------------------------------------------------------------- |
| GRIMBOLT       | support           | 24a11a26a2586f4fba7bfe89df2e21a0809ad85069e442da98c37c4add369a0c |
| GRIMBOLT       | out_elf_2         | dfb37247d12351ef9708cb6631ce2d7017897503657c6b882a711c0da8a9a591 |
| SLAYSTYLE      | default_jsp.java  | 92fb4ad6dee9362d0596fda7bbcfe1ba353f812ea801d1870e37bfc6376e624a |
| BRICKSTORM     | N/A               | aa688682d44f0c6b0ed7f30b981a609100107f2d414a3a6e5808671b112d1878 |
| BRICKSTORM     | splisten          | 2388ed7aee0b6b392778e8f9e98871c06499f476c9e7eae6ca0916f827fe65df |
| BRICKSTORM     | N/A               | 320a0b5d4900697e125cebb5ff03dee7368f8f087db1c1570b0b62f5a986d759 |
| BRICKSTORM     | N/A               | 90b760ed1d0dcb3ef0f2b6d6195c9d852bcb65eca293578982a8c4b64f51b035 |
| BRICKSTORM     | N/A               | 45313a6745803a7f57ff35f5397fdf117eaec008a76417e6e2ac8a6280f7d830 |

### File Names and Paths
- **/home/kos/tomcat9/tomcat-users.xml** (Tomcat Manager config with default credentials)
- **/var/lib/tomcat9** (WAR file upload directory)
- **/var/cache/tomcat9/Catalina** (Compiled WAR artifacts)
- **/var/log/tomcat9/** (Tomcat application logs)
- **/home/kos/auditlog/fapi_cl_audit_log.log** (Tomcat Manager web logs)
- **/home/kos/kbox/src/installation/distribution/convert_hosts.sh** (Persistence mechanism via script modification)

### Registry Keys, Mutex Names, Email Addresses
- **None reported**

### C2 Infrastructure Details
- **GRIMBOLT C2**: 149.248.11.71 (wss://149.248.11.71/rest/apisession)

---

## 2. TTPs (MITRE ATT&CK Mapping)

| Tactic              | Technique ID & Name                  | Description / Usage                                                                                  |
|---------------------|--------------------------------------|------------------------------------------------------------------------------------------------------|
| Initial Access      | T1190 - Exploit Public-Facing Application | Exploitation of CVE-2026-22769 in Dell RecoverPoint for Virtual Machines via Tomcat Manager.         |
| Initial Access      | T1133 - External Remote Services      | Targeting edge appliances (VPN concentrators) for initial access.                                    |
| Execution           | T1059.004 - Command and Scripting Interpreter: Unix Shell | Execution of shell scripts (convert_hosts.sh) for persistence and backdoor invocation.               |
| Execution           | T1505.003 - Server Software Component: Web Shell | Deployment of SLAYSTYLE web shell via malicious WAR file upload.                                     |
| Persistence         | T1036.004 - Masquerading: Masquerade Task/Service | Modification of legitimate convert_hosts.sh script to invoke malware at boot.                        |
| Persistence         | T1547.001 - Boot or Logon Initialization Scripts: Unix | Use of rc.local to execute convert_hosts.sh at boot.                                                 |
| Defense Evasion     | T1027 - Obfuscated Files or Information | Packing GRIMBOLT with UPX and using Native AOT compilation to hinder static analysis.                |
| Lateral Movement    | T1021.001 - Remote Desktop Protocol   | Pivoting into VMware infrastructure via Ghost NICs and network port creation.                        |
| Lateral Movement    | T1046 - Network Service Scanning      | Pivoting to internal/SaaS infrastructure using newly created network ports.                          |
| Command & Control   | T1071.001 - Application Layer Protocol: Web Protocols | Use of WebSocket (wss) for C2 communication.                                                        |
| Command & Control   | T1090 - Proxy                         | Use of iptables for Single Packet Authorization and traffic redirection.                             |
| Privilege Escalation| T1086 - Exploitation for Privilege Escalation | Execution of commands as root via Tomcat Manager.                                                    |

---

## 3. Malware & Tools

### Malware Families
- **GRIMBOLT**: C# backdoor, Native AOT compiled, packed with UPX, remote shell, replaces BRICKSTORM.
- **BRICKSTORM**: Previous backdoor, replaced by GRIMBOLT in recent campaigns.
- **SLAYSTYLE**: Web shell deployed via malicious WAR file.

### Legitimate Tools Abused (LOLBins)
- **Apache Tomcat Manager**: Used for deploying malicious WAR files.
- **iptables**: Used for Single Packet Authorization and traffic redirection.
- **rc.local**: Used for boot persistence.
- **Shell scripts (convert_hosts.sh)**: Modified for persistence.

### Custom Tooling
- **Ghost NICs**: Creation of temporary network ports on ESXi VMs for stealthy lateral movement.

---

## 4. Threat Actor / Campaign Attribution

- **Threat Group**: UNC6201 (suspected PRC-nexus cluster)
- **Aliases/Overlap**: UNC5221 (sometimes referred to as Silk Typhoon, but GTIG does not equate the two)
- **Campaigns**: Replacement of BRICKSTORM with GRIMBOLT (September 2025)
- **Motivation**: Espionage
- **Targeted Sectors**: Organizations using Dell RecoverPoint for Virtual Machines and VMware infrastructure
- **Geographies**: Not explicitly stated, but likely global with focus on organizations with relevant appliances

---

## 5. Splunk Detection Searches

### 5.1 Network IOC: GRIMBOLT C2 IP

```spl
# Detect outbound connections to GRIMBOLT C2 IP (149.248.11.71)
index=firewall OR index=proxy OR index=dns
(149.248.11.71 OR "wss://149.248.11.71/rest/apisession")
| stats count by src_ip, dest_ip, dest_port, uri
| where dest_ip="149.248.11.71"
```
*Detects network traffic to known C2 infrastructure.*

---

### 5.2 File Hashes: Endpoint Detection

```spl
# Search for known malicious file hashes on endpoints (Sysmon)
index=endpoint OR index=sysmon OR index=crowdstrike:events:sensor
(file_hash="24a11a26a2586f4fba7bfe89df2e21a0809ad85069e442da98c37c4add369a0c"
 OR file_hash="dfb37247d12351ef9708cb6631ce2d7017897503657c6b882a711c0da8a9a591"
 OR file_hash="92fb4ad6dee9362d0596fda7bbcfe1ba353f812ea801d1870e37bfc6376e624a"
 OR file_hash="aa688682d44f0c6b0ed7f30b981a609100107f2d414a3a6e5808671b112d1878"
 OR file_hash="2388ed7aee0b6b392778e8f9e98871c06499f476c9e7eae6ca0916f827fe65df"
 OR file_hash="320a0b5d4900697e125cebb5ff03dee7368f8f087db1c1570b0b62f5a986d759"
 OR file_hash="90b760ed1d0dcb3ef0f2b6d6195c9d852bcb65eca293578982a8c4b64f51b035"
 OR file_hash="45313a6745803a7f57ff35f5397fdf117eaec008a76417e6e2ac8a6280f7d830")
| stats count by host, file_name, file_path, file_hash
```
*Detects presence of known malicious binaries.*

---

### 5.3 Tomcat Manager Exploitation

```spl
# Detect suspicious Tomcat Manager WAR file uploads
index=web OR index=tomcat OR index=auditlog
("/manager/text/deploy" AND "PUT")
| stats count by src_ip, uri, http_method, user, file_path
```
*Identifies potential exploitation of Tomcat Manager for malicious WAR uploads.*

---

### 5.4 Persistence via Script Modification

```spl
# Detect modifications to convert_hosts.sh (Sysmon File Create/Change)
index=sysmon OR index=endpoint
(file_path="/home/kos/kbox/src/installation/distribution/convert_hosts.sh")
| stats count by host, user, file_path, action
```
*Detects persistence mechanism via script modification.*

---

### 5.5 iptables SPA/Proxying

```spl
# Detect suspicious iptables commands for SPA/proxying
index=sysmon OR index=linux_secure OR index=systemd
(CommandLine="iptables*" AND (CommandLine="--hex-string*" OR CommandLine="--dport 10443"))
| stats count by host, user, CommandLine, _time
```
*Detects use of iptables for SPA and traffic redirection.*

---

## 6. Executive Summary

UNC6201, a suspected China-based espionage group, has been actively exploiting a critical zero-day (CVE-2026-22769) in Dell RecoverPoint for Virtual Machines since mid-2024. The actor leverages default credentials and Tomcat Manager to deploy web shells and backdoors, notably transitioning from BRICKSTORM to the advanced GRIMBOLT malware. Their tactics include persistent access via script modification, lateral movement into VMware environments using Ghost NICs, and sophisticated network proxying with iptables. Organizations using affected Dell and VMware appliances should urgently apply vendor patches, audit for the listed IOCs, and review boot scripts and network logs for signs of compromise. Immediate hardening and detection are strongly recommended to mitigate ongoing risk.
