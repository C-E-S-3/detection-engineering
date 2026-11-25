---
scraped_at: 2026-11-25T04:00:00Z
source_url: https://www.cisa.gov/news-events/alerts/2026/11/24/cisa-adds-five-known-exploited-vulnerabilities-catalog
report_type: threat-intel
severity: critical
title: "CISA KEV November 24 2026: Idunno AntiCsrf CSRF Bypass, Drupal Core RCE, Optimizely Web Experimentation JS Injection, N-able MailAssure SSRF, MONAI Label Path Traversal"
---

## 1. IOCs

### File Hashes

None published for these CVEs.

### Domains / IPs

None published for these CVEs. For IOCs associated with the Optimizely Web Experimentation (CVE-2026-132224) skimmer campaign, see `2026-11-16_unit42-paloaltonetworks-com-optimjack-supply-chain-attack.md` and existing domain/IP entries in `iocs/domain.csv` and `iocs/ip.csv`.

### CVEs Added (November 24, 2026)

| CVE | Vendor / Product | Type | CVSS | Fixed Version | KEV Due Date |
|-----|-----------------|------|------|--------------|-------------|
| CVE-2026-131914 | Idunno AntiCsrf (all versions prior to 2.3.2) | CSRF validation bypass — attacker submits a crafted anti-CSRF token that passes server-side validation, enabling forged cross-site requests on behalf of authenticated users | 7.5 | 2.3.2 | 2026-12-15 |
| CVE-2026-132165 | Drupal Core (10.x prior to 10.4.3; 11.x prior to 11.1.5) | Insufficient input validation in Media Library module allows unauthenticated RCE via crafted media upload requests; exploitable without valid session | 9.8 | 10.4.3 / 11.1.5 | 2026-12-01 |
| CVE-2026-132224 | Optimizely Web Experimentation (SaaS; signup workflow) | Account signup flow weakness allows attacker-controlled account to inject arbitrary JavaScript into Optimizely CDN snippet loaded by customer websites; affects 178+ organizations via supply-chain injection | N/A (SaaS; no CVSS assigned — no versioned product) | Optimizely deployed server-side fix Nov 17, 2026; customer re-auth required | 2026-12-01 |
| CVE-2026-134624 | N-able MailAssure (all versions prior to 2026.11.3) | Server-Side Request Forgery (SSRF) in email preview endpoint allows unauthenticated attacker to reach internal services via crafted URL parameter | 9.3 | 2026.11.3 | 2026-11-26 |
| CVE-2026-133968 | MONAI Label (medical AI platform; all versions prior to 0.6.1) | Path traversal zero-day in model-upload endpoint allows unauthenticated attacker to write files to arbitrary locations on the MONAI Label server, enabling RCE via crafted model archive | 9.8 | 0.6.1 | 2026-11-26 |

---

## 2. TTPs

### CVE-2026-131914 — Idunno AntiCsrf CSRF Bypass

| MITRE Tactic | Technique ID | Technique Name | Usage |
|---|---|---|---|
| Defense Evasion | T1550 | Use Alternate Authentication Material | Forged CSRF token bypasses server-side state validation |
| Impact | T1565 | Data Manipulation | Attacker submits forged authenticated requests (account changes, data modification) on behalf of victim |

**Key indicator:** Unexpected POST requests to privileged application functions originating from unexpected referrers or cross-origin sources; CSRF token values not matching server-side session state. Affects applications using the Idunno AntiCsrf .NET library.

### CVE-2026-132165 — Drupal Core Media Library RCE

| MITRE Tactic | Technique ID | Technique Name | Usage |
|---|---|---|---|
| Initial Access | T1190 | Exploit Public-Facing Application | Unauthenticated media upload request exploits validation flaw in Drupal Media Library |
| Execution | T1059.004 | Unix Shell | Server-side code execution as the web server user (typically `www-data` or `apache`) |
| Persistence | T1505.003 | Server Software Component: Web Shell | Post-exploit web shell written to Drupal files directory |

**Key indicator:** POST requests to `/media/*/upload` or `/admin/content/media/add` from unauthenticated sessions; PHP process spawning unexpected child processes; new `.php` files in `sites/default/files/`. Exploitation does not require user authentication or specific modules beyond core Media Library.

### CVE-2026-132224 — Optimizely Web Experimentation JS Injection

| MITRE Tactic | Technique ID | Technique Name | Usage |
|---|---|---|---|
| Initial Access | T1195.002 | Supply Chain Compromise: Compromise Software Supply Chain | Attacker injects JavaScript into Optimizely CDN snippet loaded by 178+ customer websites |
| Collection | T1056.003 | Input Capture: Web Portal Capture | Injected skimmer captures payment card details and login credentials entered on victim websites |
| Impact | T1657 | Financial Theft | Captured card data and credentials used for fraudulent transactions; crypto wallet address swapping |

**Key indicator:** Unexpected JavaScript loading from non-standard CDN origins in Optimizely snippet context; `Content-Security-Policy` violations; exfiltration POST requests to `1688360[.]cc`. See OPTIMJACK IOCs in `iocs/domain.csv` lines 904–908 and `iocs/ip.csv` for `136.113.106.136`.

### CVE-2026-134624 — N-able MailAssure SSRF

| MITRE Tactic | Technique ID | Technique Name | Usage |
|---|---|---|---|
| Initial Access | T1190 | Exploit Public-Facing Application | SSRF via unauthenticated email preview endpoint |
| Discovery | T1046 | Network Service Discovery | SSRF used to scan internal network services unreachable from the internet |
| Collection | T1005 | Data from Local System | SSRF may allow access to internal metadata services (AWS IMDS, GCP metadata) for credential theft |

**Key indicator:** Unexpected outbound HTTP requests from MailAssure server to internal RFC1918 ranges or cloud metadata endpoints (169.254.169.254); URL parameters in email preview requests containing `file://`, `dict://`, `gopher://`, or `http://169.254` patterns.

### CVE-2026-133968 — MONAI Label Path Traversal Zero-Day

| MITRE Tactic | Technique ID | Technique Name | Usage |
|---|---|---|---|
| Initial Access | T1190 | Exploit Public-Facing Application | Unauthenticated path traversal via model-upload endpoint |
| Persistence | T1505.003 | Server Software Component: Web Shell | Attacker writes web-accessible files to execute server-side code |
| Execution | T1059 | Command and Scripting Interpreter | Uploaded files executed in context of MONAI Label server process |

**Key indicator:** Model upload requests with `../` sequences in filename or archive member paths; new files appearing outside expected model storage directories; MONAI Label process spawning unexpected children. MONAI Label is widely deployed in healthcare/research environments; internet-exposed instances are primary risk. No authentication required for exploitation.

---

## 3. Malware & Tools

No specific malware families published for CVE-2026-131914, CVE-2026-132165, CVE-2026-134624, or CVE-2026-133968. Active exploitation observed for all five. Post-exploitation activity consistent with:
- **Web shell deployment** (Drupal, MONAI Label)
- **Credential harvesting** (MailAssure SSRF → cloud metadata)
- **JavaScript skimmer** (Optimizely — see OPTIMJACK campaign)

---

## 4. Threat Actor / Campaign Attribution

| Attribute | Value |
|---|---|
| Attribution | Unattributed for CVE-2026-131914, CVE-2026-132165, CVE-2026-134624, CVE-2026-133968 |
| CVE-2026-132224 | OPTIMJACK campaign previously tracked — see Unit 42 report and existing IOCs |
| Targeting | CVE-2026-132165: CMS/web platform operators; CVE-2026-133968: healthcare, medical research, academic institutions running MONAI Label; CVE-2026-134624: MSPs and enterprises using N-able MailAssure |
| Federal Deadline | CVE-2026-134624 and CVE-2026-133968 require federal remediation by **November 26, 2026** (2-day window) |

---

## 5. Splunk Detection Searches

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Web.Web
  where Web.dest_category IN ("cms","web-application")
    AND Web.url IN ("*/media/*/upload*","*/admin/content/media/add*","*/monai/infer/upload*","*/monailabel/*/upload*")
    AND Web.status IN ("200","201","500")
    AND (Web.http_method="POST" OR Web.http_method="PUT")
  by Web.src Web.dest Web.url Web.http_method Web.status Web.bytes
| `drop_dm_object_name(Web)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    match(url,"(?i)monai"), 95,
    match(url,"(?i)drupal|media/upload"), 85,
    1=1, 70)
| where risk_score >= 70
| table firstTime lastTime src dest url http_method status bytes risk_score
```

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Processes
  where Processes.parent_process_name IN ("python3","python","uvicorn","gunicorn","monailabel")
    AND Processes.process_name IN ("bash","sh","dash","zsh","curl","wget","python","python3","perl","nc","ncat")
  by Processes.dest Processes.user Processes.parent_process_name Processes.process_name
     Processes.process Processes.process_id
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    match(process,"(?i)/dev/tcp|/dev/udp|mkfifo|base64.*decode|wget.*-O.*sh|curl.*sh"), 95,
    match(parent_process_name,"(?i)monailabel|uvicorn"), 90,
    1=1, 80)
| where risk_score >= 80
| table firstTime lastTime dest user parent_process_name process_name process risk_score
```

---

## 6. Executive Summary

CISA added five vulnerabilities to its KEV catalog on November 24, 2026. Two carry a highly compressed federal remediation deadline of **November 26, 2026** — just two days after publication — indicating active exploitation with critical urgency.

**CVE-2026-133968 (MONAI Label, CVSS 9.8)** is a zero-day path traversal in the medical AI platform's model-upload endpoint. Any internet-exposed MONAI Label instance prior to 0.6.1 is at risk of unauthenticated RCE. Healthcare and research operators should isolate or patch immediately.

**CVE-2026-134624 (N-able MailAssure, CVSS 9.3)** is an unauthenticated SSRF enabling internal network pivoting from MSP email infrastructure. Attackers can probe internal services and cloud metadata endpoints. Patch to 2026.11.3 or restrict access to the email preview endpoint.

**CVE-2026-132165 (Drupal Core, CVSS 9.8)** affects Drupal 10 and 11 without authentication via the Media Library module. The federal remediation deadline is December 1; however, Drupal's broad attack surface and history of rapid weaponization (Drupalgeddon 1/2) mean operators should prioritize this upgrade.

**CVE-2026-132224 (Optimizely Web Experimentation)** receives its formal KEV designation following the OPTIMJACK campaign that compromised 178 organizations via JavaScript skimmer injection. IOCs are already tracked in this repository.

**CVE-2026-131914 (Idunno AntiCsrf, CVSS 7.5)** is the lowest urgency of the five — a CSRF bypass in a .NET anti-CSRF library. Affects applications that have not yet upgraded to 2.3.2.

---

## 7. References

- [CISA KEV Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
- [WindowsForum: CISA Adds Exploited AntiCsrf, Drupal and Optimizely Flaws to KEV](https://windowsforum.com/news/cisa-adds-exploited-anticsrf-drupal-and-optimizely-flaws-to-kev-catalog.453974/)
- [Threadlinqs: CISA KEV November 24 Advisory](https://intel.threadlinqs.com/threat/TL-2026-6821)
- [lavx.hu: N-able MailAssure and MONAI Label KEV](https://news.lavx.hu/article/cisa-adds-n-able-mailassure-and-monai-label-flaws-to-kev-catalog)
- [DEV: Actively Exploited This Week — Nov 16–22, 2026 KEV Roundup](https://dev.to/devaland/actively-exploited-this-week-9-new-cisa-kev-entries-16-november-to-22-november-2026-49al)
- OPTIMJACK / CVE-2026-132224 IOCs: see `iocs/domain.csv` lines 904–908 and `iocs/ip.csv`
