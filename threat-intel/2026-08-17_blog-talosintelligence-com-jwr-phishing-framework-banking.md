---
scraped_at: 2026-08-17T00:00:00Z
source_url: https://blog.talosintelligence.com/dissecting-the-jwr-phishing-framework/
report_type: threat-intel
severity: high
title: JWR Phishing-as-a-Service Framework Targeting Australian, NZ, Singapore, and UAE Banks
---

# JWR Phishing-as-a-Service Framework Targeting Australian, NZ, Singapore, and UAE Banks

## 1. Indicators of Compromise (IOCs)

### File Hashes (SHA256)
| Hash | Description |
|------|-------------|
| 464e46e3e45dc99228aae7b0c0051d2759b937f164eeca7e34416963c195d227 | JWR framework PHP backend |
| 00f36ddd07320d492035ccc2f09142139120ed5d6b58705777647e1e4b05aacc | JWR credential harvester module |
| 1a27e992576f8aaf2c1f177c580622923d3d3a9264f43740bb1f4fb8676a7c5d | JWR admin panel |
| 917234a575bfe049b6cefcee7f8e98808bcc2753c681793ccc55b6b7c1be7017 | JWR SMS OTP relay component |

### IP Addresses (Hosting Infrastructure)
| IP | Role |
|----|------|
| 47.88.78.148 | JWR phishing kit hosting |
| 47.90.223.199 | JWR phishing kit hosting |
| 43.156.227.15 | JWR phishing kit hosting |
| 43.160.241.151 | JWR phishing kit hosting |

### Phishing Domains
| Domain | Target Brand |
|--------|-------------|
| xiaomimiyizu[.]xyz | Generic credential harvester |
| dubai[.]customszf[.]top | UAE customs / delivery scam |
| anzrewardse-homes[.]info | ANZ Bank (Australia/NZ) |
| bendigo-homesa[.]info | Bendigo Bank (Australia) |
| hsbcrewards-homesa[.]info | HSBC (Australia) |
| hsbcrewards-homesb[.]info | HSBC (Australia) — variant |
| lloydsbank-homesa[.]info | Lloyds Bank |
| qantasrewardsa-homes[.]info | Qantas Frequent Flyer (Australia) |
| qantasrewardsb-homes[.]info | Qantas Frequent Flyer — variant |
| rbcroyalbank-homesa[.]cc | RBC Royal Bank (Canada) |
| rbcroyalbank-homesc[.]info | RBC Royal Bank — variant |
| rbcroyalbank-homesd[.]info | RBC Royal Bank — variant |
| suncorp-homesa[.]info | Suncorp Bank (Australia) |
| suncorp-homesb[.]info | Suncorp Bank — variant |
| westpacone-homesc[.]info | Westpac Bank (Australia) |
| westpacone-homesg[.]info | Westpac Bank — variant |

### Additional Targeted Brands / Services (no domain IOC, operator-specific)
- Singapore LTA (Land Transport Authority) / ERP road pricing
- UAE First Abu Dhabi Bank (FAB)
- Parking and package delivery notification lures

### C2 Infrastructure
- JWR operates a real-time operator panel receiving harvested credentials and OTP codes.
- Hosting on Alibaba Cloud infrastructure (AS45102 / Alibaba US Technology).

---

## 2. TTPs (MITRE ATT&CK Mapping)

### Initial Access
- **T1566.002 - Phishing: Spearphishing Link**
  - Victims receive SMS or email with link to JWR-hosted phishing page impersonating a bank, rewards program, or government service.

- **T1598.003 - Phishing for Information: Spearphishing Link**
  - Credential harvesting pages collect username, password, date of birth, card number, CVV, and OTP codes in a multi-step wizard.

### Execution
- **T1059.007 - Command and Scripting Interpreter: JavaScript**
  - JWR phishing pages are built in PHP/JavaScript with real-time relay of entered credentials to the operator panel.

### Defense Evasion
- **T1036.005 - Masquerading: Match Legitimate Name or Location**
  - Domain names constructed with target brand names and common suffixes (`-homes`, `rewards`).

- **T1583.001 - Acquire Infrastructure: Domains**
  - Bulk registration of disposable `.info`/`.cc`/`.xyz`/`.top` domains; rapid rotation when blocked.

- **T1656 - Impersonation**
  - Full visual cloning of bank/brand login portals including logos, color schemes, and multi-factor authentication flows.

### Credential Access
- **T1056.003 - Input Capture: Web Portal Capture**
  - Multi-step phishing wizard captures: username/email, password, date of birth, card number, CVV, OTP/2FA code.

- **T1111 - Multi-Factor Authentication Interception**
  - Real-time OTP relay: victim-entered OTP is immediately forwarded to the operator who submits it to the legitimate bank portal within the one-time-password validity window.

### Exfiltration
- **T1567 - Exfiltration Over Web Service**
  - Harvested credentials and OTP codes are POST'd in real time to the JWR operator dashboard over HTTPS.

---

## 3. Malware & Tools

### Framework Components
- **JWR Backend (PHP)**: Server-side framework managing phishing kit templates, operator accounts, real-time credential relay, and campaign analytics.
- **Credential Harvester Module**: Per-page wizard logic; multi-step form capture with input validation mimicking the target bank's UX.
- **Admin Panel**: Operator dashboard showing live credential feeds, OTP codes (with countdown timer), and campaign statistics.
- **SMS OTP Relay Component**: Intercepts OTP input and forwards it to operators in real time with session context.

### Delivery Method
- Smishing (SMS phishing) and email phishing with branded lure content.
- Some lures use government/transport authority impersonation (Singapore LTA ERP, Dubai customs) for urgency.

### Infrastructure
- Hosting concentrated on Alibaba Cloud; likely purchased via resellers.
- Domain registration pattern: `<brand>(rewards|one|<letter>)-homes<letter>.<tld>` with sequential variant letters.

---

## 4. Threat Actor / Campaign Attribution

### Threat Actor
- **JWR** (Phishing-as-a-Service operator/cluster)
  - Named after framework identifier strings in kit code.
  - Likely operates as a subscription service sold to criminal customers.

### Campaigns
- Active campaigns targeting AU/NZ banks (Westpac, Suncorp, Bendigo, ANZ, Qantas Rewards, HSBC AU).
- Separate campaigns: Singapore LTA/ERP, UAE First Abu Dhabi Bank, UAE/Dubai customs.
- Canadian targeting: RBC Royal Bank variants.

### Motivations
- Financial crime: account takeover, fraudulent transfers, card-not-present fraud.

### Targeted Sectors & Geographies
- **Australia/New Zealand**: Westpac, Suncorp, Bendigo, ANZ, HSBC Australia, Qantas Frequent Flyer.
- **Singapore**: LTA/ERP electronic road pricing.
- **United Arab Emirates**: First Abu Dhabi Bank, Dubai customs.
- **Canada**: RBC Royal Bank.

---

## 5. Splunk Detection Searches

### 5.1 DNS Queries to Known JWR Phishing Domains
```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Network_Resolution.DNS
  where DNS.query IN (
    "xiaomimiyizu.xyz","dubai.customszf.top","anzrewardse-homes.info",
    "bendigo-homesa.info","hsbcrewards-homesa.info","hsbcrewards-homesb.info",
    "lloydsbank-homesa.info","qantasrewardsa-homes.info","qantasrewardsb-homes.info",
    "rbcroyalbank-homesa.cc","rbcroyalbank-homesc.info","rbcroyalbank-homesd.info",
    "suncorp-homesa.info","suncorp-homesb.info","westpacone-homesc.info",
    "westpacone-homesg.info"
  )
  by DNS.src DNS.query DNS.answer
| `drop_dm_object_name(DNS)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=95
| table firstTime lastTime src query answer count risk_score
```

### 5.2 HTTP Traffic to JWR Hosting IPs
```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Network_Traffic.All_Traffic
  where All_Traffic.dest_ip IN ("47.88.78.148","47.90.223.199","43.156.227.15","43.160.241.151")
  by All_Traffic.src_ip All_Traffic.dest_ip All_Traffic.dest_port
| `drop_dm_object_name(All_Traffic)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=90
| table firstTime lastTime src_ip dest_ip dest_port count risk_score
```

### 5.3 JWR Domain Pattern — Bank Brand Impersonation Domains
```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Network_Resolution.DNS
  where DNS.query match("^(westpac|suncorp|bendigo|anz|hsbc|qantas|rbcroyalbank|lloyds|nab|commbank|ing)[a-z]*-homes[a-z]?\.(info|cc|xyz|top|site|online)$")
  by DNS.src DNS.query DNS.answer
| `drop_dm_object_name(DNS)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=85
| where risk_score >= 85
| table firstTime lastTime src query answer count risk_score
```

### 5.4 Web Proxy — Access to Banking Phishing Kit Patterns
```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Web.Web
  where Web.url match("/(login|verify|confirm|auth|otp|sms-verify|card-verify)")
    AND Web.dest match("(westpac|suncorp|bendigo|anzrewards|qantasrewards|hsbc|rbcroyalbank|lloydsbank)")
    AND NOT Web.dest match("(westpac\.com\.au|suncorp\.com\.au|bendigobank\.com\.au|anz\.com|qantas\.com|hsbc\.com|rbcroyalbank\.com|lloydsbank\.com)")
  by Web.src Web.dest Web.url Web.user_agent Web.http_method
| `drop_dm_object_name(Web)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=80
| table firstTime lastTime src dest url user_agent http_method risk_score
```

### 5.5 JWR File Hash Detection
```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Processes
  where Processes.process_hash IN (
    "464e46e3e45dc99228aae7b0c0051d2759b937f164eeca7e34416963c195d227",
    "00f36ddd07320d492035ccc2f09142139120ed5d6b58705777647e1e4b05aacc",
    "1a27e992576f8aaf2c1f177c580622923d3d3a9264f43740bb1f4fb8676a7c5d",
    "917234a575bfe049b6cefcee7f8e98808bcc2753c681793ccc55b6b7c1be7017"
  )
  by Processes.dest Processes.user Processes.process_name Processes.process_hash
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=100
| table firstTime lastTime dest user process_name process_hash count risk_score
```

---

## 6. Executive Summary

JWR is a Phishing-as-a-Service (PhaaS) framework enabling criminal operators to run convincing, multi-step bank credential harvesting campaigns against customers of major Australian, New Zealand, Singaporean, UAE, and Canadian financial institutions. The framework provides complete infrastructure: PHP backend, per-brand phishing kit templates with full visual cloning, a real-time operator dashboard for receiving credentials, and a live OTP relay component that allows operators to defeat SMS-based two-factor authentication within the one-time-password validity window. Hosting is concentrated on Alibaba Cloud infrastructure. Domain names follow a predictable pattern embedding target brand names with `-homes` suffixes and sequential variant letters on `.info`/`.cc`/`.xyz`/`.top` TLDs. Financial institutions in the targeted regions should deploy brand-protection monitoring and report newly identified domains to their respective registrars and abuse teams. Security teams should block the identified hosting IPs and add the known domains to DNS sinkholes or proxy blocklists.
