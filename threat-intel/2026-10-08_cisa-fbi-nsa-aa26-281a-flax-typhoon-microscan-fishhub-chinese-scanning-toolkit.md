---
scraped_at: "2026-10-09T00:00:00Z"
source_url: "https://www.cisa.gov/news-events/cybersecurity-advisories/aa26-281a"
report_type: threat-intel
severity: critical
title: "AA26-281A: Flax Typhoon / Integrity Technology Group — MicroScan Automated Vulnerability Scanner and FishHub Stolen-Email Portal"
---

## 1. IOCs

### Domains (Seized by DOJ/FBI, October 8 2026)

| Indicator | Role |
|-----------|------|
| c0cc[.]cc | MicroScan admin access domain |
| 98aicai[.]com | FishHub phishing / spear-phishing delivery |
| 98aicode[.]com | FishHub spear-phishing delivery |
| outlook3650[.]com | FishHub — Microsoft Outlook lookalike lure |
| youtubecard[.]com | FishHub — fake YouTube lure domain |
| linkedinns[.]net | FishHub — fake LinkedIn lure domain |
| 98aiblog[.]com | SoftEther VPN C2 — maintains persistent access to victim networks |

### CVEs Added to CISA KEV (2026-10-08, due date 2026-10-11)

| CVE | Product | Vulnerability |
|-----|---------|--------------|
| CVE-2015-3306 | ProFTPD | mod_copy — remote unauthenticated file copy via SITE CPFR/CPTO |
| CVE-2015-5477 | ISC BIND | TKEY query denial of service (crash via assertion failure) |
| CVE-2016-3081 | Apache Struts | Remote code execution via chained OGNL evaluation (Dynamic Method Invocation) |
| CVE-2021-3199 | ONLYOFFICE | Directory traversal during image upload → command execution (JWT-enabled deployments) |
| CVE-2023-22894 | Strapi | Admin credential disclosure to authenticated users via REST API field filters (v3.2.1–4.7.9) |

### Hashes

No file hashes published in the advisory.

### IPs

No specific C2 IPs published in the unclassified advisory.

---

## 2. TTPs (MITRE ATT&CK)

| Tactic | Technique ID | Technique Name | Usage |
|--------|-------------|----------------|-------|
| Reconnaissance | T1595.002 | Active Scanning: Vulnerability Scanning | MicroScan — Python-based scanner with 1,300+ exploit scripts targeting Oracle WebLogic, Apache Struts, WordPress, Jenkins, and other applications |
| Initial Access | T1190 | Exploit Public-Facing Application | Exploitation of CVE-2015-3306, CVE-2016-3081, CVE-2021-3199, CVE-2023-22894, CVE-2015-5477 against internet-facing services |
| Credential Access | T1110.003 | Brute Force: Password Spraying | EBurst — open-source tool used to password-spray Microsoft Exchange OWA, EWS, and Exchange Online endpoints at scale |
| Credential Access | T1114.002 | Email Collection: Remote Email Collection | FishHub web portal ingests stolen mailboxes exfiltrated via EBurst; provides third-party clients read access to stolen email content |
| Persistence | T1133 | External Remote Services | SoftEther VPN software installed on compromised hosts via 98aiblog[.]com infrastructure; maintains persistent access to victim networks |
| Defense Evasion | T1078.004 | Valid Accounts: Cloud Accounts | Use of stolen Microsoft 365 credentials obtained via EBurst to blend in with legitimate user activity |
| Collection | T1114 | Email Collection | Bulk mailbox exfiltration via scripted queries against compromised Exchange/M365 accounts |
| Exfiltration | T1567 | Exfiltration Over Web Service | FishHub resells stolen email to third-party clients via web portal |
| Resource Development | T1584.004 | Compromise Infrastructure: Server | MicroScan compromises internet-facing servers via the above CVEs to build operational relay infrastructure |

---

## 3. Malware & Tools

| Tool | Type | Description |
|------|------|-------------|
| MicroScan | Vulnerability Scanner | Python-based automated scanner containing 1,300+ penetration-testing scripts; identifies security flaws across Oracle WebLogic, Apache Struts, WordPress, Jenkins, network devices, and other internet-facing applications |
| FishHub | Email Exfiltration Portal | Web application enabling third-party clients to query and read stolen email content; operated by Integrity Technology Group on behalf of Chinese intelligence-linked customers |
| EBurst | Password Sprayer | Open-source Microsoft Exchange/M365 password-spraying tool; targets OWA, EWS, Exchange Online Basic Auth, and IMAP endpoints; used to harvest email credentials at scale |
| SoftEther VPN | Persistent Access | Installed on compromised hosts to maintain long-term persistent remote access; C2 communicated via 98aiblog[.]com before domain seizure |

---

## 4. Threat Actor / Campaign Attribution

| Field | Detail |
|-------|--------|
| Primary Actor | **Integrity Technology Group** — China-based for-profit cybersecurity company under US and UK sanctions; assessed to work on behalf of the Chinese Ministry of State Security (MSS) |
| Track Names | Flax Typhoon (Microsoft), Ethereal Panda (CrowdStrike), Red Juliett (Recorded Future) |
| Activity Period | Mid-2021 through October 2026 (6+ year campaign) |
| Targeting | US critical manufacturing, healthcare, IT, government services, law enforcement, education, and religious organizations; Southeast Asia, Africa, and North America |
| Previous Disruption | September 2024: FBI disrupted an earlier Flax Typhoon botnet of ~260,000 devices; current advisory documents the reconstituted campaign |
| Relationship | Assessed overlap with i-SOON (Anxun Information Technology) — a separate Chinese contractor; Integrity Technology Group operated as a competitor and periodic business partner |

Advisory co-authored by: FBI, CISA, NSA (United States); NCSC-UK, NCSC-NZ, NCSC-AU, and agencies in Canada, Germany, and the Netherlands. The advisory is AA26-281A and the accompanying PDF runs 58 pages.

---

## 5. Splunk Detection Searches

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Network_Traffic.All_Traffic
  where All_Traffic.dest IN ("c0cc.cc","98aicai.com","98aicode.com","outlook3650.com",
                              "youtubecard.com","linkedinns.net","98aiblog.com")
  by All_Traffic.src All_Traffic.dest All_Traffic.dest_port All_Traffic.app
| `drop_dm_object_name(All_Traffic)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=95
| table firstTime lastTime src dest dest_port app risk_score
```

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Authentication
  where Authentication.action="failure"
    AND Authentication.app IN ("OWA","Exchange Web Services","Microsoft Exchange","Office365")
  by Authentication.src Authentication.dest Authentication.user
| `drop_dm_object_name(Authentication)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| stats dc(user) as distinct_users count as total_failures
    min(firstTime) as firstTime max(lastTime) as lastTime
    by src dest
| where distinct_users > 10 AND total_failures > 50
| eval risk_score=case(distinct_users > 50, 90, distinct_users > 20, 75, 1=1, 60)
| where risk_score >= 60
| table firstTime lastTime src dest distinct_users total_failures risk_score
```

```spl
index=* (url="/modules/mod_copy.php" OR
         url="*SITE%20CPFR*" OR url="*SITE%20CPTO*" OR
         url="*struts2*redirect*" OR url="*onlyoffice*fileUpload*")
| eval risk_score=case(
    url LIKE "%SITE%20CPFR%" OR url LIKE "%SITE%20CPTO%", 90,
    url LIKE "%struts2*redirect%", 85,
    1=1, 70)
| where risk_score >= 70
| stats count min(_time) as firstTime max(_time) as lastTime
    by src_ip url dest risk_score
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| table firstTime lastTime src_ip dest url risk_score
```

---

## 6. Executive Summary

On October 8, 2026, the FBI, CISA, NSA, and partners in six additional countries released joint advisory AA26-281A documenting a six-year campaign by Integrity Technology Group — a Chinese cybersecurity firm operating on behalf of Chinese intelligence — that uses two main tools: **MicroScan**, a Python-based vulnerability scanner containing over 1,300 exploit scripts, and **FishHub**, a web portal that resells stolen email content to third-party clients.

The campaign is tracked across the industry as Flax Typhoon (Microsoft), Ethereal Panda (CrowdStrike), and Red Juliett (Recorded Future). It targets US critical infrastructure, healthcare, government, law enforcement, education, and religious organizations, as well as victims across Southeast Asia, Africa, and North America.

On the same day, the DOJ and FBI seized seven Integrity Technology Group domains and disrupted both tools. CISA added five CVEs to the Known Exploited Vulnerabilities Catalog with a 3-day remediation deadline (2026-10-11): ProFTPD CVE-2015-3306, ISC BIND CVE-2015-5477, Apache Struts CVE-2016-3081, ONLYOFFICE CVE-2021-3199, and Strapi CVE-2023-22894.

Organizations should immediately:
1. Patch all five newly added KEV CVEs by October 11.
2. Search for any connections to the 7 seized domains.
3. Audit Microsoft Exchange/M365 for bulk mailbox access by scripted user agents.
4. Disable legacy Exchange authentication protocols (Basic Auth, NTLM for OWA/EWS) that EBurst exploits.
5. Review SoftEther VPN processes on servers (any instance is anomalous outside of approved deployments).
