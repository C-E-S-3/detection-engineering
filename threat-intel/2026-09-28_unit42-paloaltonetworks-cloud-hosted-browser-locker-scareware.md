---
scraped_at: 2026-09-28T12:30:00Z
source_url: https://raw.githubusercontent.com/PaloAltoNetworks/Unit42-timely-threat-intel/main/2026-09-28-Cloud-Hosted-Browser-Locker-Scareware.txt
report_type: threat-intel
severity: medium
title: "Cloud-Hosted Browser Locker Scareware: AWS Amplify Delivery with Vishing Callback for Tech Support Fraud"
---

# Cloud-Hosted Browser Locker Scareware: AWS Amplify Delivery with Vishing Callback for Tech Support Fraud

## 1. IOCs

### Domains
| Indicator | Type | Context |
|-----------|------|---------|
| `hitrelay[.]com` | Redirect | Browser locker traffic relay and redirect service; used to route victims to scareware payload pages |
| `blog.birdjournal[.]com` | Compromised | Compromised legitimate blog; used as cloaking layer to evade URL reputation blockers |
| `main[.]d1sgde6tm4rzhv[.]amplifyapp[.]com` | Payload | AWS Amplify-hosted browser locker scareware page; locks browser and displays fake Microsoft security alert |

### Vishing Phone Numbers
| Number | Context |
|--------|---------|
| +1(844)449-0284 | Tech support fraud callback number displayed by browser locker |
| +1(844)449-5490 | Tech support fraud callback number (alternate) |

---

## 2. TTPs

| Tactic | Technique ID | Technique | Usage |
|--------|-------------|-----------|-------|
| Initial Access | TA0001 | T1566.002 | Phishing — malvertising redirects via `hitrelay[.]com` to scareware payload; SEO abuse and ad network abuse to drive traffic |
| Execution | TA0002 | T1204.001 | User Execution: Malicious Link — victim clicks ad or search result, triggering redirect chain |
| Command and Control | TA0011 | T1219 | Remote Access Software — vishing operator requests victim install RMM software (AnyDesk, TeamViewer) as part of "tech support" social engineering |
| Credential Access | TA0006 | T1056.001 | Input Capture: Keylogging — operator with RMM access captures credentials entered during "support session" |
| Defense Evasion | TA0005 | T1027 | Obfuscated Files or Information — JavaScript browser locker uses obfuscated JS and fullscreen API abuse to trap victim browser |
| Defense Evasion | TA0005 | T1608.006 | Stage Capabilities: SEO Poisoning — malvertising and paid placement used to surface scareware delivery URLs |

---

## 3. Malware & Tools

**Browser Locker (Scareware)**
- **Type:** JavaScript browser locker delivered via AWS Amplify-hosted page
- **Delivery chain:** Malvertising / SEO poisoning → `hitrelay[.]com` redirect → compromised `blog.birdjournal[.]com` (cloaking) → `*.amplifyapp.com` payload
- **Mechanism:** JavaScript forces browser into fullscreen, intercepts keyboard/pointer events to prevent navigation, displays fake Microsoft Windows Defender or Windows Security alert claiming the system is infected
- **Goal:** Panic victim into calling displayed "Microsoft support" phone number
- **Post-call:** Operator requests remote access (AnyDesk, TeamViewer, QuickAssist) to "fix" the infection; uses access to steal banking credentials, install backdoors, or charge fraudulent fees
- **AWS Amplify hosting:** Abuses cloud CDN to distribute from a trusted domain/TLS certificate, defeating many web proxy category filters

---

## 4. Threat Actor / Campaign Attribution

Unattributed tech support fraud operation. The use of AWS Amplify for payload hosting, a dedicated redirect relay (`hitrelay[.]com`), and two active vishing callback numbers indicates an organized operation. Tech support scams of this type are predominantly attributed to criminal organizations in South/Southeast Asia operating at scale against English-speaking victims in the US, UK, Canada, and Australia.

---

## 5. Splunk Detection Searches

### Detect Navigation to Known Browser Locker Infrastructure
```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Web.Web
  where Web.url="*hitrelay.com*"
    OR Web.url="*d1sgde6tm4rzhv.amplifyapp.com*"
  by Web.src Web.dest Web.url Web.user Web.http_user_agent
| `drop_dm_object_name(Web)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    match(url,"amplifyapp.com"), 80,
    match(url,"hitrelay.com"), 85,
    1=1, 70)
| where risk_score >= 70
| table firstTime lastTime src dest url user http_user_agent risk_score
```

### Detect DNS Queries to Browser Locker Domains
```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Network_Resolution.DNS
  where DNS.query IN ("hitrelay.com","blog.birdjournal.com")
  by DNS.src DNS.query DNS.answer
| `drop_dm_object_name(DNS)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    query="hitrelay.com", 85,
    1=1, 60)
| where risk_score >= 60
| table firstTime lastTime src query answer risk_score
```

### Detect Unsolicited RMM Installation Following Browser Activity (Correlation)
```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Processes
  where Processes.process_name IN ("AnyDesk.exe","TeamViewer.exe","QuickAssist.exe",
    "msra.exe","ScreenConnect.ClientService.exe")
    AND Processes.parent_process_name IN ("chrome.exe","msedge.exe","firefox.exe",
    "iexplore.exe","opera.exe","brave.exe")
  by Processes.dest Processes.user Processes.parent_process_name
     Processes.process_name Processes.process_id
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=90
| table firstTime lastTime dest user parent_process_name process_name risk_score
```

---

## 6. Executive Summary

Unit 42 (Palo Alto Networks) published intelligence on September 28, 2026 documenting a cloud-hosted browser locker scareware campaign that abuses **AWS Amplify** for payload delivery and a dedicated traffic relay service (`hitrelay[.]com`) to route victims through a cloaking layer.

**Attack chain:** Malvertising or SEO-poisoned search results direct victims to `hitrelay[.]com`, which relays them through a compromised legitimate blog (`blog.birdjournal[.]com`) for URL reputation evasion before finally landing on an AWS Amplify-hosted JavaScript browser locker page. The browser locker traps the user's browser in fullscreen, intercepts navigation attempts, and displays a fake Microsoft Windows Defender security alert claiming the system is critically infected. The page displays tech support callback numbers: `+1(844)449-0284` or `+1(844)449-5490`.

**Social engineering:** When victims call, operators impersonate Microsoft support and request remote access via AnyDesk, TeamViewer, or QuickAssist. The remote session is then used to steal banking credentials, install persistent backdoors, or charge fraudulent "repair" fees.

**AWS Amplify abuse:** The use of AWS Amplify (`*.amplifyapp.com`) as the payload host is notable — many web proxy policies allowlist AWS CDN domains, and the HTTPS certificate is valid. This allows the scareware page to bypass URL reputation filters that would catch a self-hosted malicious domain.

**Detection:** Block `hitrelay[.]com` at DNS/proxy. Alert on browser processes (Chrome, Edge, Firefox) spawning remote support tools (AnyDesk, TeamViewer, QuickAssist) — this correlation is a strong indicator of a social engineering session in progress.

---

## References

- [Unit 42 Timely Threat Intel — Cloud-Hosted Browser Locker Scareware (2026-09-28)](https://github.com/PaloAltoNetworks/Unit42-timely-threat-intel)
- [MITRE ATT&CK T1219 — Remote Access Software](https://attack.mitre.org/techniques/T1219/)
- [MITRE ATT&CK T1204.001 — User Execution: Malicious Link](https://attack.mitre.org/techniques/T1204/001/)
- [FTC Tech Support Scams](https://consumer.ftc.gov/articles/how-avoid-tech-support-scams)
- [AWS Amplify security documentation](https://docs.aws.amazon.com/amplify/latest/userguide/security.html)
