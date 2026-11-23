---
scraped_at: 2026-11-23T08:00:00Z
source_url: https://www.cisa.gov/news-events/alerts/2026/11/20/cisa-adds-four-known-exploited-vulnerabilities-catalog
report_type: threat-intel
severity: high
title: "CISA KEV November 20 2026: SAP NetWeaver JNDI Injection, Cisco Expressway OS Command Injection, Apache Roller XML-RPC Deserialization RCE"
---

## 1. IOCs

### File Hashes

None published for these CVEs.

### Domains / IPs

None published for these CVEs.

### CVEs Added (November 20, 2026)

| CVE | Vendor / Product | Type | CVSS | Fixed Version | KEV Due Date |
|-----|-----------------|------|------|--------------|-------------|
| CVE-2025-42884 | SAP NetWeaver Enterprise Portal (EP-BASIS / EP-RUNTIME 7.50) | JNDI Injection — unauthenticated remote attacker injects JNDI lookup URL to reach unintended JNDI providers | 6.5 | SAP Security Note 3660969 | 2026-11-23 |
| CVE-2026-76466 | Cisco Expressway Core / Expressway Edge (X15.5.3 and earlier; also X14 and earlier) | OS command injection via TLS clustering — unauthenticated root command execution on clustered Expressway devices | 9.8 | X15.5.20 (X14 must migrate) | 2026-11-23 |
| CVE-2026-129448 | Apache Roller 4.0.0–6.1.4 | XML-RPC deserialization — unauthenticated attacker calls `/roller-services/xmlrpc` with extension-typed parameters that are deserialized before session validation | 9.8 | 6.1.6 | 2026-11-24 |
| CVE-2026-123890 | VMware vCenter (various) | Authentication bypass | 9.8 | Per VMSA-2026-0017 | 2026-11-10 (tracked in ARMORY CASTLE report 2026-11-19) |

---

## 2. TTPs

### CVE-2025-42884 — SAP NetWeaver JNDI Injection

| MITRE Tactic | Technique ID | Technique Name | Usage |
|---|---|---|---|
| Initial Access | T1190 | Exploit Public-Facing Application | Unauthenticated JNDI injection via SAP Enterprise Portal; can reach arbitrary JNDI providers for class loading |
| Execution | T1059.007 | JavaScript | JNDI-loaded remote classes execute server-side code in JVM context |
| Collection | T1005 | Data from Local System | Post-exploit access to Portal content, user credentials, and SAP system configuration |

**Key indicator:** Unexpected outbound LDAP/RMI connections from SAP NetWeaver JVM process (following JNDI injection weaponization pattern similar to Log4Shell). Affected component: EP-BASIS and EP-RUNTIME 7.50. No privileges or user interaction required.

### CVE-2026-76466 — Cisco Expressway OS Command Injection

| MITRE Tactic | Technique ID | Technique Name | Usage |
|---|---|---|---|
| Initial Access | T1190 | Exploit Public-Facing Application | Exploitation via TLS clustering mechanism; only affects devices configured with TLS Verify Mode for clustering |
| Execution | T1059.004 | Unix Shell | Root-level OS command execution on Expressway appliance |
| Persistence | T1098.004 | Account Manipulation: SSH Authorized Keys | Likely post-exploit SSH key injection for persistent root access |
| Discovery | T1016 | System Network Configuration Discovery | Pivot to internal collaboration infrastructure after initial Expressway compromise |

**Key indicator:** `nodeup` entry in Erlang system log (`erlang.log`) indicates cluster exploitation attempt. F6 observed attackers compromising two internet-facing devices then reaching two more cluster nodes internally. PoC published to GitHub November 5, 2026.

### CVE-2026-129448 — Apache Roller XML-RPC Deserialization RCE

| MITRE Tactic | Technique ID | Technique Name | Usage |
|---|---|---|---|
| Initial Access | T1190 | Exploit Public-Facing Application | Unauthenticated POST to `/roller-services/xmlrpc` with malicious extension-type parameter triggers deserialization before session validation |
| Execution | T1059.004 | Unix Shell | Deserialized payload executes OS commands as the JVM service user (typically `tomcat`) |
| Persistence | T1505.003 | Server Software Component: Web Shell | Post-exploit web shell deployment to Roller application directories |
| Defense Evasion | T1027 | Obfuscated Files or Information | Deserialization gadget chains obfuscate the actual payload |

**Key indicator:** Tomcat/JVM process spawning unexpected shell children; POST requests to `/roller-services/xmlrpc` with XML containing `<value><ex:serializable>` or similar extension-type tags. Turning off XML-RPC in the Admin UI is **not** sufficient on vulnerable releases. Must patch to 6.1.6 or disable in `WEB-INF/web.xml`.

---

## 3. Malware & Tools

No specific malware families associated with these CVEs at time of reporting. Post-exploitation activity consistent with:
- **Web shell deployment** (observed following similar Java deserialization flaws)
- **Generic reverse shells** (curl/wget/bash one-liners via RCE)
- **Credential harvesting** (database config files, SAP portal credentials)

---

## 4. Threat Actor / Campaign Attribution

| Attribute | Value |
|---|---|
| Attribution | Unattributed; active exploitation confirmed for CVE-2025-42884 and CVE-2026-129448 per CISA KEV addition |
| Cisco Expressway | F6 observed exploitation by an unnamed threat actor shortly after PoC release November 5, 2026 |
| Targeting | SAP NetWeaver: enterprise ERP/portal environments; Cisco Expressway: enterprise voice/video conferencing; Apache Roller: Java blog platforms (academic, government, tech) |

---

## 5. Splunk Detection Searches

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Processes
  where Processes.parent_process_name IN ("java","java.exe","catalina.sh","startup.sh","roller.sh")
    AND Processes.process_name IN ("bash","sh","dash","zsh","cmd.exe","powershell.exe","pwsh.exe",
                                    "curl","wget","nc","ncat","python","python3","perl","ruby")
  by Processes.dest Processes.user Processes.parent_process_name Processes.process_name
     Processes.process Processes.process_id
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    match(process,"(?i)base64|/dev/tcp|/dev/udp|wget|curl.*sh|mkfifo"), 95,
    match(parent_process_name,"(?i)catalina|roller"), 90,
    1=1, 80)
| where risk_score >= 80
| table firstTime lastTime dest user parent_process_name process_name process risk_score
```

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Web.Web
  where Web.url="*/roller-services/xmlrpc*"
    AND Web.http_method="POST"
    AND Web.status IN ("200","500")
  by Web.src Web.dest Web.url Web.http_method Web.status Web.bytes
| `drop_dm_object_name(Web)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    bytes > 1000, 90,
    1=1, 75)
| where risk_score >= 75
| table firstTime lastTime src dest url http_method status bytes risk_score
```

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Filesystem
  where Filesystem.file_path IN ("*/roller/WEB-INF/*","*/webapps/roller/*","*/tomcat/webapps/*")
    AND Filesystem.file_name IN ("*.jsp","*.jspx","*.php","*.war")
    AND (Filesystem.action="created" OR Filesystem.action="modified")
  by Filesystem.dest Filesystem.user Filesystem.file_path Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=90
| where risk_score >= 90
| table firstTime lastTime dest user file_path file_name risk_score
```

---

## 6. Executive Summary

CISA added four vulnerabilities to its KEV catalog on November 20, 2026, with an unusually tight federal remediation deadline of November 23–24, 2026. Three of the four represent new coverage in this repository (CVE-2026-123890/VMware vCenter is tracked in the ARMORY CASTLE threat-intel report from November 19):

**CVE-2026-129448 (Apache Roller, CVSS 9.8)** is the highest-priority item. The XML-RPC endpoint deserializes extension-typed parameters before validating session credentials, enabling unauthenticated code execution on any internet-facing Roller instance running 4.0.0–6.1.4. Apache has confirmed active exploitation. Patch to 6.1.6 or disable the XML-RPC servlet entirely in `WEB-INF/web.xml`. Simply disabling XML-RPC in the Admin UI is insufficient on vulnerable versions.

**CVE-2026-76466 (Cisco Expressway, CVSS 9.8)** affects clustered Expressway deployments. F6 confirmed exploitation began within days of a November 5 PoC drop, with attackers pivoting from two internet-facing devices to two additional internal cluster nodes. Upgrade to X15.5.20; X14 installations must migrate to X15.

**CVE-2025-42884 (SAP NetWeaver EP, CVSS 6.5)** is a JNDI injection in the Enterprise Portal that follows the Log4Shell exploitation pattern — unauthenticated injection of a JNDI lookup URL triggers remote class loading from attacker-controlled LDAP/RMI servers. Apply SAP Security Note 3660969. Despite the lower CVSS score, JNDI injection in JVM applications historically enables full RCE via deserialization gadget chains.
