---
scraped_at: 2026-11-26T00:00:00Z
source_url: https://www.cisa.gov/news-events/alerts/2026/11/25/cisa-adds-10-known-exploited-vulnerabilities-catalog
report_type: threat-intel
severity: critical
title: "CISA KEV Nov 25 2026 — 10 Exploited Flaws: Mitel MiCollab AWV Command Injection (CVSS 10.0), Xen Orchestra Auth Bypass, Juniper Session Smart OS Injection, Danfoss AK-SM"
---

# CISA KEV November 25 2026 — 10 Actively Exploited Vulnerabilities

## 1. IOCs

No attacker-controlled infrastructure (domains, IPs, hashes) has been publicly attributed to exploitation of these CVEs as of this report. The following artifact is associated with post-exploitation of Vates Xen Orchestra:

| Type | Indicator | Context |
|------|-----------|---------|
| VM Name | `pivot2` | Attacker-created pivot VM observed on compromised XCP-ng hypervisors after CVE-2026-133469 exploitation (Vates advisory VSA-2026-062; treat as preliminary pending confirmation) |

---

## 2. TTPs (MITRE ATT&CK)

| Tactic | Technique ID | Technique Name | Usage |
|--------|-------------|----------------|-------|
| Initial Access | T1190 | Exploit Public-Facing Application | All 10 CVEs exploit remotely accessible services — UC platform (Mitel), hypervisor management (Xen Orchestra), network conductor (Juniper), and OT SCADA controller (Danfoss) |
| Execution | T1059.004 | Unix Shell | Mitel MiCollab AWV CVE-2026-133323 enables unauthenticated blind OS command injection; attacker executes arbitrary shell commands via HTTP parameter manipulation |
| Privilege Escalation | T1078.003 | Cloud Accounts — Valid Accounts | Xen Orchestra CVE-2026-133469: empty-object token attack returns first valid admin session; attacker gains full hypervisor management access with admin privileges on first API call |
| Defense Evasion | T1070.001 | Clear Windows Event Logs | Observed attacker behavior post-Xen Orchestra compromise includes clearing hypervisor management audit trails |
| Impact | T1496 | Resource Hijacking | Post-exploitation of Mitel and Danfoss flaws includes deployment of crypto miners (observed in prior similar campaigns against enterprise appliances) |

---

## 3. Malware & Tools

No confirmed malware families associated with exploitation of these CVEs as of publication. Prior campaigns against enterprise UC platforms have deployed:
- Reverse shells (bash, Python, Perl)
- Web shells (PHP, JSP) for persistence
- Credential stealers targeting stored UC platform credentials

---

## 4. Threat Actor / Campaign Attribution

No specific threat actor has been publicly attributed to active exploitation of these vulnerabilities as of 2026-11-26. CISA added all ten entries citing "evidence of active exploitation" per the standard KEV criteria. The five Mitel MiCollab CVEs were added the same day as Mitel's advisory MISA-2026-0012.

---

## 5. Splunk Detection Searches

### 5a. Mitel MiCollab AWV OS Command Injection — Java Web Process Spawning Shell (CVE-2026-133323)

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Endpoint.Processes
where (Processes.parent_process_name IN ("java", "java.exe")
       OR Processes.parent_process="/usr/java/*"
       OR Processes.parent_process="*/micollab*"
       OR Processes.parent_process="*/mitel*")
  AND Processes.process_name IN ("sh","bash","dash","ksh","zsh","python","python3",
                                   "curl","wget","nc","ncat","netcat","perl","ruby",
                                   "id","whoami","cat","base64","chmod","chown")
by Processes.dest Processes.user Processes.parent_process_name Processes.parent_process
   Processes.process_name Processes.process Processes.process_id
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    match(process_name,"^(nc|ncat|netcat)$"), 95,
    match(process_name,"^(curl|wget)$") AND match(process,"http"), 90,
    match(process_name,"^(id|whoami)$"), 80,
    1=1, 70)
| where risk_score >= 70
| table firstTime lastTime dest user parent_process_name parent_process process_name process risk_score
```

**What it detects:** Java/JVM web application processes (Tomcat, Jetty) spawning OS interpreter or recon tools; directly covers CVE-2026-133323 unauthenticated blind command injection via MiCollab AWV HTTP parameters.

### 5b. Vates Xen Orchestra Auth Bypass — Empty-Object Token Attack (CVE-2026-133469)

```spl
`xen_orchestra` earliest=-15m
| rex field=_raw "\"userId\":\"(?<userId>[^\"]+)\""
| rex field=_raw "\"authToken\":(?<authToken>\{[^}]*\}|\"[^\"]*\")"
| eval is_empty_token=if(match(authToken,"^\{\s*\}$") OR authToken="{}", "true", "false")
| where is_empty_token="true"
| stats count min(_time) as firstTime max(_time) as lastTime by src_ip userId
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=95
| table firstTime lastTime src_ip userId count risk_score
```

**What it detects:** REST API authentication attempts with an empty-object token (`{}`), which is the precise attack vector for CVE-2026-133469. Any successful or attempted authentication with this token pattern should be investigated immediately.

### 5c. Juniper Session Smart Conductor OS Command Injection — Appliance Web Process Shell Spawn (CVE-2026-103406)

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Endpoint.Processes
where (Processes.parent_process_name IN ("conductor","128t-gui","salt-master","gunicorn","uwsgi","nginx","httpd")
       OR Processes.parent_process="*/128technology*"
       OR Processes.parent_process="*/juniper*")
  AND Processes.process_name IN ("sh","bash","python","python3","curl","wget","nc","ncat")
by Processes.dest Processes.user Processes.parent_process_name Processes.parent_process
   Processes.process_name Processes.process
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=90
| table firstTime lastTime dest user parent_process_name parent_process process_name process risk_score
```

**What it detects:** Juniper Session Smart Conductor web management process spawning OS shells; covers CVE-2026-103406 OS command injection in Conductor management API (CVSS 9.8).

---

## 6. Executive Summary

On November 25, 2026, CISA added 10 actively exploited vulnerabilities to the Known Exploited Vulnerabilities (KEV) catalog. The batch is dominated by five flaws in Mitel MiCollab's Audio, Web, and Video (AWV) component (Mitel advisory MISA-2026-0012), including a **CVSS 10.0 unauthenticated blind OS command injection** (CVE-2026-133323) that allows attackers to execute arbitrary system commands without authentication on MiCollab servers running version 10.3.0.18 and earlier.

A **Vates Xen Orchestra authentication bypass** (CVE-2026-133469, CVSS 9.8) in the same batch uses a JavaScript empty-object cookie parsing quirk to authenticate as a valid admin without credentials, granting full control over XCP-ng hypervisor hosts. Post-exploitation indicators include an attacker-created VM named "pivot2." A **Juniper Session Smart Conductor OS command injection** (CVE-2026-103406, CVSS 9.8) rounds out the high-impact network infrastructure targets, alongside three Danfoss AK-SM 800A SCADA controller flaws (CVE-2023-25914, CVE-2023-25915, CVE-2025-41450).

**Federal civilian agencies must patch by November 28, 2026** for most entries (December 9 for CVE-2026-133311 and CVE-2025-41450). No specific threat actor has been attributed. The concentration of UC, hypervisor management, and network conductor targets suggests opportunistic wide-net exploitation across enterprise and OT environments.

---

## References

- [CISA KEV Alert — November 25, 2026](https://www.cisa.gov/news-events/alerts/2026/11/25/cisa-adds-10-known-exploited-vulnerabilities-catalog)
- [Mitel MISA-2026-0012 — MiCollab AWV Multiple Vulnerabilities](https://www.mitel.com/en-us/support/security-advisories)
- [CVE-2026-133323 — Mitel MiCollab AWV Unauthenticated OS Command Injection (CVSS 10.0)](https://ostorlab.co/mitel-micollab-awv-command-injection-cve-2026-133323.html)
- [CVE-2026-133469 — Vates Xen Orchestra Empty-Object Auth Bypass (CVSS 9.8)](https://dev.to/iamfaizanakhtar/cve-2026-133469-xen-orchestra-authentication-bypass-via-empty-object-token-analysis-mitigation-1i00)
- [BleepingComputer — Xen Orchestra Auth Bypass Exploited](https://www.bleepingcomputer.com/news/security/critical-xen-orchestra-auth-bypass-flaw-exploited-to-hijack-vm-servers/)
- [CISA KEV Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
- [MITRE ATT&CK T1190 — Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/)
