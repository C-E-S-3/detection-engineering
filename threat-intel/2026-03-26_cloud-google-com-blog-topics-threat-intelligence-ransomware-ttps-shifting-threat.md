---
scraped_at: 2024-06-10T17:00:00Z
source_url: https://cloud.google.com/blog/topics/threat-intelligence/ransomware-ttps-shifting-threat-landscape
report_type: threat-intel
---

# Threat Intelligence Report: Ransomware TTPs in a Shifting Threat Landscape

## 1. Indicators of Compromise (IOCs)

**IP addresses (IPv4/IPv6):**
- *Not provided in the source.*

**Domains and URLs:**
- Data Leak Sites (DLS): CL0P DLS, FUNKSEC DLS (no explicit URLs provided)
- Negotiation sites hosted via ICP blockchain (no explicit URLs provided)

**File hashes (MD5, SHA1, SHA256):**
- *Not provided in the source.*

**Email addresses used in campaigns:**
- *Not provided in the source.*

**File names and paths:**
- LOCKBIT.WARLOCK (ransomware payload, file name implied)

**Registry keys:**
- *Not provided in the source.*

**Mutex names:**
- *Not provided in the source.*

**C2 infrastructure details:**
- DEADLOCK ransomware leveraging Polygon smart contracts for C2 rotation
- Cry0 RaaS using ICP blockchain for negotiation site hosting

---

## 2. TTPs (MITRE ATT&CK Mapping)

| Tactic              | Technique ID & Name           | Description / Usage Observed |
|---------------------|------------------------------|------------------------------|
| Initial Access      | T1190 - Exploit Public-Facing Application | Exploitation of vulnerabilities in VPNs, firewalls (Fortinet, SonicWall, Palo Alto, Citrix), and other exposed services (Veritas, Zoho, Sharepoint, SAP Netweaver). Zero-day exploitation observed. |
| Initial Access      | T1078 - Valid Accounts        | Use of stolen credentials for access. |
| Initial Access      | T1110 - Brute Force           | Brute force attacks against exposed services. |
| Initial Access      | T1059 - Command and Scripting Interpreter | Web compromise for initial access. |
| Execution           | T1204 - User Execution        | Deployment of ransomware payloads post-compromise. |
| Persistence         | T1136 - Create Account        | Creation of new accounts for persistence (implied). |
| Defense Evasion     | T1562 - Impair Defenses       | Use of tools like MIMIKATZ, BEACON (decreased usage noted). |
| Credential Access   | T1003 - OS Credential Dumping | Use of MIMIKATZ for credential harvesting (decreased usage noted). |
| Discovery           | T1087 - Account Discovery     | Discovery of accounts and privileges (implied). |
| Lateral Movement    | T1021 - Remote Services       | Use of remote management tools (plateau in usage). |
| Exfiltration        | T1041 - Exfiltration Over C2 Channel | Data theft extortion operations. |
| Impact              | T1486 - Data Encrypted for Impact | Ransomware deployment to encrypt data. |
| Impact              | T1489 - Service Stop          | Targeting virtualization infrastructure (implied disruption of services). |
| Impact              | T1490 - Inhibit System Recovery | Preventing recovery (implied). |
| Command & Control   | T1102 - Web Service           | Use of Web3 (ICP, Polygon) for resilient C2 infrastructure. |

---

## 3. Malware & Tools

**Malware Families:**
- REDBIKE (most frequently deployed ransomware in 2025)
- LOCKBIT.WARLOCK
- MYTHICAGENT
- Qilin (RaaS)
- Akira (RaaS)
- Basta (RaaS)
- RansomHub (RaaS)
- CL0P (primarily data theft extortion)
- BABUK 2.0 (fabricated/exaggerated claims)
- Cry0 (RaaS, uses ICP blockchain)
- DEADLOCK (uses Polygon smart contracts)
- GLOBAL (RaaS, AI-assisted chat)
- CHAOS (RaaS, AI chatbot)
- BERT (AI-based data analysis)

**Legitimate Tools Abused (LOLBins):**
- BEACON (Cobalt Strike, decreased usage)
- MIMIKATZ (decreased usage)
- Remote management tools (plateau in usage)

**Custom Tooling:**
- AI-assisted negotiation and victim analysis bots (GLOBAL, CHAOS, BERT)
- Web3-based C2 and negotiation infrastructure (Cry0, DEADLOCK)

---

## 4. Threat Actor / Campaign Attribution

**Named Threat Groups:**
- UNC6357 (exploited Sharepoint vulnerabilities for LOCKBIT.WARLOCK deployment)
- UNC2165 (leveraged zero-day for MYTHICAGENT deployment)

**Campaign Names:**
- Ransomware-as-a-Service (RaaS) operations: Qilin, Akira, Basta, RansomHub, CL0P, BABUK 2.0, Cry0, DEADLOCK, GLOBAL, CHAOS, BERT

**Known Affiliations or Motivations:**
- Financially motivated (ransomware, data theft extortion)
- Shift toward data theft extortion due to declining ransomware profits

**Targeted Sectors and Geographies:**
- Asia Pacific, Europe, North America, South America
- Nearly every industry sector, with increased focus on smaller organizations (<200 employees)

---

## 5. Splunk Detection Searches

### Exploitation of VPN/Firewall Vulnerabilities (T1190)
```spl
# Detect access attempts to vulnerable VPN/firewall endpoints (Fortinet, SonicWall, Palo Alto, Citrix)
index=firewall OR index=network sourcetype=pan:firewall OR sourcetype=fortinet OR sourcetype=sonicwall
| search (uri_path="/remote" OR uri_path="/vpn" OR uri_path="/gateway" OR uri_path="/mgmt")
| stats count by src_ip, dest_ip, uri_path, _time
| where count > 10
# Comment: Identifies repeated access attempts to common VPN/firewall endpoints, indicative of exploitation attempts.
```

### Brute Force Authentication Attempts (T1110)
```spl
# Detect brute force login attempts across VPN, firewall, and web services
index=auth OR index=firewall sourcetype=pan:firewall OR sourcetype=fortinet OR sourcetype=sonicwall OR sourcetype=windows
| stats count by src_ip, user, action, _time
| where action="failed" AND count > 20
# Comment: Flags repeated failed authentication attempts, suggesting brute force activity.
```

### Suspicious Use of MIMIKATZ (T1003)
```spl
# Detect MIMIKATZ execution on endpoints (Sysmon)
index=endpoint sourcetype=XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
| search (Image="*mimikatz.exe*" OR CommandLine="*sekurlsa*")
| stats count by host, user, Image, CommandLine, _time
# Comment: Identifies potential credential dumping using MIMIKATZ.
```

### Ransomware Payload Deployment (T1486)
```spl
# Detect creation of known ransomware payloads (e.g., LOCKBIT.WARLOCK, REDBIKE)
index=endpoint sourcetype=XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
| search (Image="*LOCKBIT.WARLOCK*" OR Image="*redbike*" OR Image="*mythicagent*")
| stats count by host, user, Image, _time
# Comment: Flags execution of known ransomware payloads.
```

### Data Exfiltration to Web3/Blockchain C2 (T1102)
```spl
# Detect outbound connections to blockchain-related domains (ICP, Polygon)
index=proxy OR index=dns sourcetype=proxy OR sourcetype=dns
| search (dest_domain="*.icp.network*" OR dest_domain="*.polygon.io*")
| stats count by src_ip, dest_domain, _time
# Comment: Identifies potential C2 or negotiation traffic to blockchain infrastructure.
```

### Data Leak Site Access (DLS)
```spl
# Detect access to known DLS domains (CL0P, FUNKSEC)
index=proxy OR index=dns sourcetype=proxy OR sourcetype=dns
| search (dest_domain="cl0p-leaksite.com" OR dest_domain="funksec-leaksite.com")
| stats count by src_ip, dest_domain, _time
# Comment: Monitors for access to data leak sites, which may indicate extortion or victim notification.
```

---

## 6. Executive Summary

Ransomware remains a pervasive and evolving threat, with 2025 marking record activity on data leak sites and a shift toward data theft extortion as profitability declines. Threat actors are increasingly exploiting vulnerabilities in VPNs, firewalls, and exposed services, often leveraging zero-day exploits for initial access. The ransomware ecosystem is adapting by integrating AI and Web3 technologies to enhance negotiation and infrastructure resilience, while targeting smaller organizations with less mature security. Immediate actions should include patching known vulnerabilities, monitoring for brute force and credential harvesting activity, and tracking access to blockchain and DLS infrastructure. Enhanced detection and rapid response capabilities are critical as threat actors continue to innovate and shift tactics.
