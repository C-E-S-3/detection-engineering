# Citrix NetScaler CVE-2026-107406 SAML Memory Overflow Exploitation Attempt

## Description

Detects exploitation attempts and post-exploitation activity targeting CVE-2026-107406, a critical pre-authentication memory overflow vulnerability in Citrix NetScaler ADC and Gateway appliances configured as SAML Identity Providers or Service Providers. A malformed SAML assertion sent to the SAML endpoint triggers memory corruption, potentially enabling unauthenticated remote code execution.

Disclosed October 8, 2026 (Citrix advisory CTX697191). No confirmed in-the-wild exploitation at disclosure, but the prior vulnerability in the same SAML codebase (CVE-2026-88779) was weaponized within days of disclosure.

False positives for the SAML POST monitoring rule are possible from oversized SAML assertions from legitimate federated identity providers. The post-exploitation process spawn rule should have very low false positive rates on properly hardened NetScaler appliances.

## MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| **Tactic** | Initial Access |
| **Tactic ID** | TA0001 |
| **Technique** | Exploit Public-Facing Application |
| **Technique ID** | T1190 |
| **CVE** | CVE-2026-107406 |
| **Secondary Tactic** | Execution (TA0002) — post-exploitation process execution |
| **Secondary Technique** | T1059 — Command and Scripting Interpreter |

## Lockheed Martin Kill Chain Phase

Exploitation

## Splunk SPL Query

### Detection 1: Anomalous POST to NetScaler SAML Endpoint

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Web.Web
  where Web.http_method="POST"
    (Web.url="*/saml/*" OR Web.url="*/samlauth/*" OR Web.url="*/cgi/samlauth*"
     OR Web.url="*/cgi/logout*" OR Web.url="*/vpn/index.html*")
    Web.bytes > 8192
  by Web.src Web.dest Web.url Web.http_user_agent Web.status Web.bytes Web.user
| `drop_dm_object_name(Web)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    bytes > 524288, 80,
    bytes > 65536, 70,
    bytes > 8192 AND match(http_user_agent,"(?i)(python|curl|wget|go-http|nmap|scanner)"), 75,
    status IN ("500","503","400","413"), 65,
    true(), 50)
| where risk_score >= 50
| table firstTime lastTime src dest url bytes status http_user_agent risk_score
```

### Detection 2: Post-Exploitation — Unexpected Process Spawned by NetScaler Daemon

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Processes
  where Processes.parent_process_name IN ("nsppe","nsapimgr","nsconf","nshttp","nscollect")
    NOT Processes.process_name IN ("nsppe","nsapimgr","nsconf","nshttp","nscollect",
      "nsshell","nscp","nsnitro","bash","sh")
  by Processes.dest Processes.user Processes.parent_process_name
     Processes.process_name Processes.process Processes.process_id
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=95
| table firstTime lastTime dest user parent_process_name process_name process process_id risk_score
```

### Detection 3: Webshell Drop on NetScaler Appliance

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Filesystem
  where (Filesystem.file_path="/var/nslog/*" OR Filesystem.file_path="*/flash/nsconfig/*"
    OR Filesystem.file_path="*/var/nstmp/*" OR Filesystem.file_path="*/netscaler/portal/themes/*")
    Filesystem.action="created"
    (Filesystem.file_name="*.php" OR Filesystem.file_name="*.sh"
     OR Filesystem.file_name="*.py" OR Filesystem.file_name="*.pl"
     OR Filesystem.file_name="*.jsp" OR Filesystem.file_name="*.aspx")
  by Filesystem.dest Filesystem.user Filesystem.file_path Filesystem.file_name Filesystem.process_name
| `drop_dm_object_name(Filesystem)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=95
| table firstTime lastTime dest user file_path file_name process_name risk_score
```

## Risk Score Logic

| Score | Condition |
|-------|-----------|
| 95 | Unexpected child process from NetScaler daemon, or webshell/script creation on appliance paths — confirmed post-exploitation |
| 80 | SAML POST with payload >512KB — highly anomalous; likely exploit attempt |
| 75 | SAML POST from scanner/tool user agent with oversized body |
| 70 | SAML POST payload >64KB — suspicious size |
| 65 | SAML POST returning HTTP 500/503 — server-side crash consistent with memory corruption |
| 50 | SAML POST payload >8KB — anomalous but may be legitimate; correlate with other indicators |

## Associated Threat Actors

| Threat Actor | Attribution | Notes |
|---|---|---|
| WHIPSHOT/SLAPSHOT Operators | Unknown | Exploited prior Citrix CVEs (CVE-2026-88771/88779); similar TTP profile expected if CVE-2026-107406 is weaponized |
| UNC3569 (suspected) | China-nexus | Exploited NetScaler CVE-2026-88779 per community reporting |

## References

- [Citrix Advisory CTX697191 (CVE-2026-107406)](https://support.citrix.com/article/CTX697191)
- [BleepingComputer: Citrix warns admins to patch new NetScaler RCE flaw immediately](https://www.bleepingcomputer.com/news/security/citrix-warns-admins-to-patch-new-netscaler-rce-flaw-immediately/)
- [SOCPrime: CVE-2026-107406 Critical NetScaler ADC and Gateway RCE Vulnerability](https://socprime.com/blog/cve-2026-107406-critical-netscaler-rce-flaw/)
- [MITRE ATT&CK: T1190 — Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/)
- Threat intel report: `threat-intel/2026-10-09_citrix-ctx697191-cve-2026-107406-netscaler-saml-rce-advisory.md`
- Related detection: `detections/initial_access/citrix_netscaler_cve_2026_88779_saml_exploit.md`
