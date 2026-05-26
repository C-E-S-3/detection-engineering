---
scraped_at: "2026-05-26T00:00:00Z"
source_url: "https://cloud.google.com/blog/topics/threat-intelligence/chinese-language-phishing-services"
report_type: threat-intel
severity: high
title: "2 PhaaS 2 Furious: Chinese-Language Phishing-as-a-Service Evolution — Darcula (UNC5814) and YY Lai Yu Adopt RCS Delivery, Real-Time OTP Interception, and Digital Wallet Tokenization"
---

## 1. IOCs

No specific domains, IPs, or file hashes were disclosed in this report. The following are structural IOC patterns and infrastructure characteristics:

**Infrastructure patterns:**
- Phishing domains impersonating Japanese consumer brands: Amazon, Apple, PayPay, Rakuten, Nintendo, Japan Post, NTT Docomo, AU, SoftBank, and utility providers (electricity, gas, water)
- Domain registrations via Alibaba's domain registration service (MIIT-registered Chinese registrars)
- Hosting on Chinese cloud providers with automatic provisioning APIs for rapid site turnover

**Lure themes (Japan-market focus):**
- Winter electricity/gas subsidy claim portals
- Loyalty points expiration notices
- Toll road payment outstanding balance
- Parcel delivery reconfirmation

---

## 2. TTPs (MITRE ATT&CK)

| Tactic | Technique ID | Technique Name | Usage |
|--------|-------------|----------------|-------|
| Initial Access | T1566.002 | Phishing: Spearphishing Link | Phishing links delivered via RCS (Rich Communication Services) and Apple iMessage; end-to-end encryption bypasses SMS carrier filters that block bulk smishing |
| Credential Access | T1539 | Steal Web Session Cookie | Real-time OTP interception via PhaaS admin panels; operators relay credentials before token expiration |
| Collection | T1056.004 | Input Capture: Credential API Hooking | Victim-submitted payment card data, OTPs, and session tokens captured in real time by PhaaS backend |
| Resource Development | T1587.001 | Develop Capabilities: Malware | AI-powered page generation (LLM-based HTML/CSS/JavaScript cloning of legitimate brand sites) enables rapid creation of high-fidelity phishing pages |
| Defense Evasion | T1656 | Impersonation | Human verification anti-bot screens (manual click requirements) prevent automated analysis; legitimate brand imagery and localized content |
| Impact | T1657 | Financial Theft | Stolen card data is immediately tokenized into Apple Pay / Google Pay digital wallet assets for contactless ATM withdrawal and POS fraud before victim cancels physical card |

---

## 3. Malware & Tools

| Tool | Type | Notes |
|------|------|-------|
| Darcula PhaaS platform | Phishing-as-a-Service | AI-powered page generator (LLM-based); Puppeteer browser automation for site cloning; real-time admin panel; multi-factor credential capture; linked to UNC5814 |
| YY Lai Yu (YY来鱼) | Phishing-as-a-Service | Chinese-language PhaaS targeting Japan (119-country template library); real-time OTP relay; loyalty-points lure specialization; advertised August 2024; operators: "YY Lai Yu," "Jeffrey Carrie," "Very casual" |

---

## 4. Threat Actor / Campaign Attribution

| Actor | Type | Notes |
|-------|------|-------|
| UNC5814 | Cybercrime (Chinese-speaking) | Linked by Google Threat Intelligence Group to Darcula PhaaS platform operations; uses AI to automate high-fidelity phishing page generation |
| "YY Lai Yu" operators | Cybercrime (Chinese-speaking) | Operate YY Lai Yu (YY来鱼) PhaaS; primarily target Japanese consumers; known aliases: "YY Lai Yu," "Jeffrey Carrie," "Very casual" |
| Unnamed Chinese-language PhaaS providers (12+) | Cybercrime ecosystem | Google identifies over a dozen distinct Chinese-language PhaaS operators in the underground market; most offer Japan-focused templates with local social-engineering lures |

**Campaign Scope:** Campaigns primarily targeting Japanese consumers impersonating domestic brands. Japan's combination of high smartphone adoption, preference for link-based service notifications, and large population of less security-aware older users makes it the primary market for this infrastructure.

---

## 5. Splunk Detection Searches

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Web.Web
where Web.uri_category="phishing" OR Web.uri_query LIKE "%/verify%" OR Web.uri_query LIKE "%/confirm%"
  AND Web.http_user_agent LIKE "%iPhone%" OR Web.http_user_agent LIKE "%Android%"
by Web.src Web.dest Web.uri_path Web.uri_query Web.http_user_agent Web.http_method
| `drop_dm_object_name(Web)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=40
| table firstTime lastTime src dest uri_path uri_query http_user_agent risk_score
```

```spl
`o365`
| search Workload=AzureActiveDirectory OR Workload=Exchange
| where Operation IN ("UserLoggedIn","FileDownloaded","AnonymousLinkCreated")
| eval suspicious=if(match(UserAgent,"(?i)(python-requests|okhttp|libcurl)"),1,0)
| where suspicious=1
| stats count min(_time) as firstTime max(_time) as lastTime by UserId, Operation, UserAgent, ClientIP
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=65,
       context="Potential PhaaS operator post-login automation (non-browser UA on authenticated session)"
| table firstTime lastTime UserId Operation UserAgent ClientIP risk_score context
```

---

## 6. Executive Summary

On May 25, 2026, Google Threat Intelligence Group published "2 PhaaS 2 Furious," an in-depth analysis of the evolving Chinese-language Phishing-as-a-Service (PhaaS) ecosystem, focusing on two operators: **Darcula** (linked to UNC5814) and **YY Lai Yu** (YY来鱼). The report documents a significant maturation from credential harvesting toward direct financial account control.

**Key novel developments:**

1. **RCS and iMessage delivery** — Campaigns have shifted from SMS (filtered by carriers) to RCS and Apple iMessage, where end-to-end encryption prevents carrier-level content scanning.

2. **Real-time OTP interception** — PhaaS admin panels now relay harvested OTPs to operators in real time, enabling session hijacking before tokens expire.

3. **Digital wallet tokenization** — Stolen payment card data is immediately provisioned into Apple Pay or Google Pay digital wallets. Tokenized assets allow fraudulent contactless transactions and ATM withdrawals even after the victim cancels the physical card, dramatically extending the fraud window.

4. **AI-powered page generation** — Large language models generate pixel-accurate clones of legitimate brand websites with localized content, enabling rapid deployment of new phishing pages.

5. **Hyper-localized lures** — Japan-specific social engineering lures (electricity subsidy portals, loyalty points expiration, toll road billing) achieve high victim click rates with culturally resonant pretexts.

These developments collectively lower the time-to-fraud window from hours to minutes and complicate traditional card fraud detection. Organizations with Japanese employee or customer populations should implement MFA methods resistant to real-time relay (e.g., FIDO2 passkeys), monitor for non-browser user agents on authenticated sessions, and deploy mobile device management policies blocking sideloaded messaging applications.
