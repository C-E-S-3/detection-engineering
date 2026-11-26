# Mitel MiCollab AWV Unauthenticated OS Command Injection (CVE-2026-133323)

## Description

Detects post-exploitation behavior following unauthenticated blind OS command injection in Mitel MiCollab's Audio, Web, and Video (AWV) component (CVE-2026-133323, CVSS 10.0). The vulnerability allows an unauthenticated remote attacker to submit crafted HTTP parameters to the AWV web service, causing the underlying Java application server to spawn arbitrary OS processes. The AWV service runs on a Linux-based MiCollab server under a service account; successful exploitation results in the Java parent process (Tomcat/Jetty) spawning shell interpreters, network utilities, or reconnaissance tools.

Added to CISA KEV on November 25, 2026 (Mitel advisory MISA-2026-0012). Affects MiCollab version 10.3.0.18 and earlier; fixed in 10.3.1.0.

**False positives:** Legitimate administrative scripts may invoke `curl` or `python` from the same Java process context during maintenance windows. Tune on the `dest` field to known MiCollab server hostnames and baseline expected parent-child process pairs before enabling alerting. Java processes that are NOT the MiCollab AWV service should be excluded by host scope.

## MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| **Tactic** | Initial Access |
| **Tactic ID** | TA0001 |
| **Technique** | Exploit Public-Facing Application |
| **Technique ID** | T1190 |
| **Secondary Technique** | Command and Scripting Interpreter: Unix Shell (T1059.004) |

## Lockheed Martin Kill Chain Phase

**Exploitation** — Attacker triggers pre-auth command injection via crafted HTTP request to the MiCollab AWV service; initial foothold on the UC server is achieved without credentials.

## Splunk SPL Query

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Endpoint.Processes
where (Processes.parent_process_name IN ("java", "java.exe")
       OR Processes.parent_process="*/micollab*"
       OR Processes.parent_process="*/mitel*"
       OR Processes.parent_process="/usr/java/*")
  AND Processes.process_name IN ("sh","bash","dash","ksh","zsh",
                                   "python","python3","python2",
                                   "curl","wget","nc","ncat","netcat",
                                   "perl","ruby","id","whoami",
                                   "cat","base64","chmod","chown","awk","sed")
by Processes.dest Processes.user Processes.parent_process_name Processes.parent_process
   Processes.process_name Processes.process Processes.process_id
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    match(process_name,"^(nc|ncat|netcat)$"), 95,
    match(process_name,"^(bash|sh|dash|ksh|zsh)$"), 90,
    match(process_name,"^(curl|wget)$") AND match(process,"http"), 88,
    match(process_name,"^(id|whoami)$"), 80,
    match(process_name,"^(python|python3|python2|perl|ruby)$"), 78,
    1=1, 70)
| where risk_score >= 70
| table firstTime lastTime dest user parent_process_name parent_process process_name process process_id risk_score
```

## Risk Score Logic

| Risk Score | Condition | Rationale |
|-----------|-----------|-----------|
| 95 | `nc`, `ncat`, `netcat` spawned from Java | Near-certain reverse shell setup; no legitimate admin use case |
| 90 | Shell interpreter (`bash`, `sh`, `dash`) spawned from Java web process | Direct OS command injection artifact; immediate investigation required |
| 88 | `curl` or `wget` with HTTP URL in process args | Likely stage-2 payload download following initial injection |
| 80 | `id` or `whoami` | Classic post-exploitation recon; confirms code execution |
| 78 | Interpreted language (`python`, `perl`, `ruby`) | Could be a stager or interactive shell dropper |
| 70 | Other process names matching the allow-list | Suspicious but lower confidence; corroborate with web server access logs |

Scores 90–95 should alert immediately (Critical). Scores 70–89 should be queued for analyst review within the same shift (High to Medium).

## Associated Threat Actors

No specific threat actor has been attributed to active exploitation of CVE-2026-133323 as of the detection authoring date (2026-11-26). Enterprise UC platform vulnerabilities are historically targeted by:

| Actor | Type | TTPs |
|-------|------|------|
| FIN7 | Financial crime / ransomware affiliate | Exploits appliance web interfaces for initial access, deploys ransomware |
| TA505 | Financially motivated | Opportunistic exploitation of unpatched enterprise appliances |
| Unknown ransomware affiliates | Ransomware-as-a-service | Scan-and-exploit campaigns targeting newly KEV-listed vulnerabilities |

## References

- [Mitel MISA-2026-0012 — MiCollab AWV Multiple Vulnerabilities](https://www.mitel.com/en-us/support/security-advisories)
- [CISA KEV Alert — November 25, 2026 (10 exploited CVEs)](https://www.cisa.gov/news-events/alerts/2026/11/25/cisa-adds-10-known-exploited-vulnerabilities-catalog)
- [CVE-2026-133323 Detail — Ostorlab](https://ostorlab.co/mitel-micollab-awv-command-injection-cve-2026-133323.html)
- [CISA KEV Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
- [MITRE ATT&CK T1190 — Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/)
- [MITRE ATT&CK T1059.004 — Unix Shell](https://attack.mitre.org/techniques/T1059/004/)
