---
scraped_at: 2024-06-10T16:00:00Z
source_url: https://cloud.google.com/blog/topics/threat-intelligence/brickstorm-espionage-campaign
report_type: threat-intel
---

# Threat Intelligence Report: BRICKSTORM Espionage Campaign

## 1. Indicators of Compromise (IOCs)

**Note:** The campaign is characterized by high operational security and minimal reuse of atomic IOCs. Most IOCs are behavioral or contextual rather than static. However, some infrastructure and file path patterns are noted.

### IP Addresses
- Example IP referenced: `10.0.0.255` (used in VAMI logs; likely internal, but indicative of appliance access patterns)

### Domains and URLs
- C2 infrastructure observed using:
  - Cloudflare Workers
  - Heroku applications
  - `sslip.io`
  - `nip.io`
- No specific C2 domains provided; domains are unique per victim and not reused.

### File Names and Paths
- `/path/to/brickstorm` (generic path for BRICKSTORM backdoor)
- `/opt/vmware/etc/init.d/vami-lighttp` (modified for persistence)
- `/etc/sysconfig/init` (modified for persistence)
- `/web/saml2/sso/*` (targeted URI for credential harvesting via BRICKSTEAL filter)

### Registry Keys
- None specified.

### File Hashes
- None provided; samples are unique per victim.

### Email Addresses
- None provided.

### Mutex Names
- None provided.

### C2 Infrastructure Details
- C2 via Cloudflare Workers, Heroku, and dynamic DNS services (`sslip.io`, `nip.io`).
- No static IPs or domains reused across victims.

---

## 2. TTPs (MITRE ATT&CK Mapping)

| Tactic                  | Technique ID & Name                | Description / Usage                                                                                  |
|-------------------------|------------------------------------|------------------------------------------------------------------------------------------------------|
| Initial Access          | T1190 - Exploit Public-Facing Application | Exploitation of zero-day vulnerabilities in network appliances for perimeter access.                |
| Execution               | T1059 - Command and Scripting Interpreter | Use of post-exploitation scripts with anti-forensics functions.                                      |
| Persistence             | T1547.001 - Boot or Logon Initialization Scripts | Modification of `init.d`, `rc.local`, or `systemd` files to launch BRICKSTORM on reboot.            |
| Persistence             | T1505.003 - Server Software Component | Installation of malicious Java Servlet filter (BRICKSTEAL) in Apache Tomcat for vCenter.            |
| Persistence             | T1505.004 - Web Shell               | Deployment of SLAYSTYLE/BEEFLUSH JSP web shell for remote command execution.                        |
| Privilege Escalation    | T1078 - Valid Accounts              | Use of captured legitimate credentials for lateral movement and privilege escalation.               |
| Credential Access       | T1556.003 - Credential Dumping: NTDS | Cloning Domain Controller VMs to extract Active Directory database (`ntds.dit`).                    |
| Credential Access       | T1552.001 - Unsecured Credentials: Credentials in Files | Extraction of credentials from password vaults and PowerShell scripts.                              |
| Defense Evasion         | T1027 - Obfuscated Files or Information | Use of Garble for obfuscation and in-memory modifications to avoid detection.                       |
| Defense Evasion         | T1070.004 - Indicator Removal on Host | Removal of BRICKSTORM samples post-operation.                                                       |
| Lateral Movement        | T1021.004 - SSH                     | Use of SSH with valid credentials to move between appliances and enable SSH services.               |
| Collection              | T1114.002 - Email Collection: Mailbox | Use of Microsoft Entra ID Enterprise Applications with mail.read/full_access_as_app scopes.         |
| Exfiltration            | T1041 - Exfiltration Over C2 Channel | Use of BRICKSTORM SOCKS proxy to tunnel and exfiltrate data.                                        |
| Impact                  | T1529 - System Shutdown/Reboot      | Manipulation of appliance startup scripts for persistence.                                           |

---

## 3. Malware & Tools

### Malware Families
- **BRICKSTORM**: Go-based backdoor with SOCKS proxy functionality, deployed on Linux/BSD appliances and VMware vCenter/ESXi hosts.
- **BRICKSTEAL**: Malicious Java Servlet filter for Apache Tomcat, used for credential harvesting.
- **SLAYSTYLE / BEEFLUSH**: JSP web shell for remote command execution.

### Legitimate Tools Abused (LOLBins)
- **sed**: Used to modify startup scripts for persistence.
- **SSH**: Used for lateral movement and appliance access.
- **VMware vCenter/ESXi management interfaces**: Used to clone VMs and enable SSH.
- **Delinea (Thycotic) Secret Server**: Targeted for credential extraction.
- **PowerShell**: Credentials harvested from scripts.

### Custom Tooling
- **wssoft library**: Custom library used in newer BRICKSTORM variants.
- **Post-exploitation scripts**: Anti-forensics and credential harvesting.

---

## 4. Threat Actor / Campaign Attribution

- **Threat Actor**: UNC5221 (suspected China-nexus cluster)
- **Aliases**: Sometimes referenced as Silk Typhoon, but GTIG distinguishes between the two.
- **Campaign Name**: BRICKSTORM
- **Motivation**: Espionage; focus on long-term stealthy access, data theft, and potential zero-day development.
- **Targeted Sectors**: Legal services, SaaS providers, BPOs, Technology.
- **Geographies**: Primarily United States.
- **Operational Security**: High; no reuse of C2 domains or malware samples, minimal security telemetry.

---

## 5. Splunk Detection Searches

### 5.1 Appliance Startup Script Modification (Persistence)
```spl
# Detect suspicious modifications to appliance startup scripts (init.d, rc.local, systemd)
index=os OR index=linux sourcetype=linux_audit OR sourcetype=syslog
| search (command="sed" AND ("/opt/vmware/etc/init.d/vami-lighttp" OR "/etc/sysconfig/init"))
| stats count by host, user, command, _time
```
*Detects use of `sed` to modify startup scripts for persistence.*

### 5.2 Suspicious SSH Enablement via VAMI
```spl
# Detect SSH enablement actions via VMware Appliance Management Interface (VAMI)
index=vmware sourcetype=vami_logs
| search "PUT /rest/appliance/access/ssh"
| stats count by src_ip, dest_ip, user, _time
```
*Detects SSH service enablement on vCenter/ESXi appliances.*

### 5.3 Web Shell Access (SLAYSTYLE/BEEFLUSH)
```spl
# Detect access to suspicious JSP web shells on vCenter servers
index=web sourcetype=tomcat_access OR sourcetype=apache_access
| search uri_path="/web/saml2/sso/" OR uri_path="*.jsp"
| stats count by src_ip, uri_path, user, _time
```
*Detects access to web shell URIs and credential harvesting endpoints.*

### 5.4 VM Cloning Events (Credential Dumping)
```spl
# Detect VM cloning activity in vSphere VPXD logs
index=vmware sourcetype=vpxd_logs
| search "VirtualMachine.clone" OR "VmClonedEvent"
| stats count by user, vm_name, _time
```
*Detects cloning of sensitive VMs, which may indicate credential dumping.*

### 5.5 Microsoft Entra ID Mailbox Access
```spl
# Detect suspicious mailbox access via Enterprise Applications (mail.read/full_access_as_app)
index=m365 sourcetype=ual
| search (operation="Mail.Read" OR operation="full_access_as_app")
| stats count by user, app_id, mailbox, _time
```
*Detects mailbox access using high-privilege application scopes.*

### 5.6 C2 Infrastructure Patterns (sslip.io, nip.io)
```spl
# Detect DNS queries or network connections to dynamic DNS C2 domains
index=network sourcetype=dns OR sourcetype=proxy
| search (query="*.sslip.io" OR query="*.nip.io")
| stats count by src_ip, dest_domain, _time
```
*Detects connections to C2 domains using dynamic DNS services.*

---

## 6. Executive Summary

The BRICKSTORM espionage campaign, attributed to UNC5221 and suspected China-nexus threat clusters, targets US-based legal, SaaS, BPO, and technology sectors with highly evasive tactics. The actor exploits zero-day vulnerabilities in network appliances, deploys the BRICKSTORM backdoor for persistent access, and leverages advanced anti-forensics and credential harvesting techniques. Operational security is extremely high, with no reuse of C2 domains or malware samples, making detection reliant on behavioral TTPs rather than atomic IOCs. Organizations should immediately reevaluate their threat models for appliances, conduct TTP-based hunts, and monitor for suspicious modifications to startup scripts, SSH enablement, web shell activity, and anomalous mailbox access. The urgency is elevated due to the actor's long dwell times and stealthy lateral movement capabilities.
